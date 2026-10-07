package server

import (
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

// MonitoredItemService implements the MonitoredItem Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12
type MonitoredItemService struct {
	SubService *SubscriptionService
	Mu         sync.Mutex

	// items tracked by ID
	Items map[uint32]*MonitoredItem
	// items tracked by node
	Nodes map[string][]*MonitoredItem
	// items tracked by subscription
	Subs map[uint32][]*MonitoredItem

	id uint32

	// nodeLocks serializes delivery (the attribute read plus the hand-off to the
	// subscription) per node now that neither happens under Mu. Without this, two
	// overlapping ChangeNotifications calls for the same node can have their reads
	// and hand-offs interleave, so a goroutine that read an older value can store
	// it after one that read a newer value, leaving the stale value as "latest" in
	// a subscriber's publish queue. Never acquire Mu while holding one of these --
	// lock ordering here is always nodeLocks entry, then (separately, inside
	// collectNotifications) Mu, never the reverse. The only lock taken while a
	// node lock is held is a subscription's leaf pendingMu.
	nodeLocks sync.Map // map[string]*sync.Mutex
}

// nodeLock returns the mutex serializing delivery for the given node key,
// creating it on first use. Entries are never removed; the key space is the
// set of distinct monitored node IDs, which is bounded by the address space,
// not by how many change events occur.
func (s *MonitoredItemService) nodeLock(key string) *sync.Mutex {
	v, _ := s.nodeLocks.LoadOrStore(key, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// function to get rid of all references to a specific Monitored Item (by ID number)
func (s *MonitoredItemService) DeleteMonitoredItem(id uint32) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	item, ok := s.Items[id]
	if !ok {
		// id does not exist.
		return
	}

	if item == nil || item.Req == nil || item.Req.ItemToMonitor == nil || item.Req.ItemToMonitor.NodeID == nil {
		return
	}
	nodeid := item.Req.ItemToMonitor.NodeID.String()

	if s == nil || s.Nodes == nil || s.Nodes[nodeid] == nil {
		return
	}

	// delete the monitored item from all nodes
	// was using slices.DeleteFunc but that is from a newer go version so we'll do it manually with /exp/slices
	// we've got to go backwards because we're deleting from the slice as we go.
	// I'm guessing this loop is less efficient than slices.DeleteFunc but it's what we've got.
	delete(s.Items, id)
	for i := len(s.Nodes[nodeid]) - 1; i >= 0; i-- {
		n := s.Nodes[nodeid][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.Nodes[nodeid] = slices.Delete(s.Nodes[nodeid], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Nodes[nodeid], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.Nodes[nodeid]) == 0 {
		delete(s.Nodes, nodeid)
	}

	for i := len(s.Subs[item.Sub.ID]) - 1; i >= 0; i-- {
		n := s.Subs[item.Sub.ID][i]
		if n == nil {
			continue
		}
		if n.ID == id {
			s.Subs[item.Sub.ID] = slices.Delete(s.Subs[item.Sub.ID], i, i+1)
		}
	}
	//slices.DeleteFunc(s.Subs[item.Sub.ID], func(i *MonitoredItem) bool { return i.ID == item.ID })
	if len(s.Subs[item.Sub.ID]) == 0 {
		delete(s.Subs, item.Sub.ID)
	}
}

// function to delete all monitored items associated with a specific sub (as indicated by id number)
func (s *MonitoredItemService) DeleteSub(id uint32) {
	s.Mu.Lock()
	items, ok := s.Subs[id]
	delete(s.Subs, id)
	s.Mu.Unlock()
	if !ok {
		return
	}
	for i := range items {
		if items[i] != nil {
			s.DeleteMonitoredItem(items[i].ID)
		}
	}
}

// namespaceLookup caches one Server.Namespace result for the length of a single
// ChangeNotifications call.
type namespaceLookup struct {
	ns  NameSpace
	err error
}

// pendingNotification is one monitored item that needs telling about a node
// change. It is captured under MonitoredItemService.Mu so that the notification
// itself can be built and delivered after the lock has been released.
type pendingNotification struct {
	sub          *Subscription
	clientHandle uint32
	node         *ua.NodeID
	attributeID  ua.AttributeID
	ns           namespaceLookup
}

// ChangeNotification tells every monitored item watching n that its value changed.
func (s *MonitoredItemService) ChangeNotification(n *ua.NodeID) {
	s.ChangeNotifications([]*ua.NodeID{n})
}

// ChangeNotifications is the batch form of ChangeNotification. A caller that
// changes many nodes at once -- one decoded message fanning out to one node per
// field, say -- pays a single Mu acquisition for the whole set instead of one per
// node.
//
// Notifications are collected under Mu and delivered after it is released. Sending
// while holding the lock is what let a single subscriber that had stopped draining
// its notification queue wedge Mu permanently, and with it every later
// CreateMonitoredItems / DeleteMonitoredItems / DeleteSubscriptions handler, since
// a subscription's run() goroutine calls DeleteSubscription on its way out and that
// needs the same mutex.
//
// Delivery itself (see deliver) never waits on a subscriber, and is serialized per
// node so a slow or reordered goroutine can't deliver a stale value after a
// fresher one already landed.
func (s *MonitoredItemService) ChangeNotifications(nodes []*ua.NodeID) {
	// Server.Namespace takes the server mutex, so resolve namespaces up front
	// rather than nesting that lock under Mu. Every node in a batch usually shares
	// one namespace, hence the cache.
	lookups := make(map[uint16]namespaceLookup, 1)
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if _, ok := lookups[n.Namespace()]; ok {
			continue
		}
		ns, err := s.SubService.srv.Namespace(int(n.Namespace()))
		lookups[n.Namespace()] = namespaceLookup{ns: ns, err: err}
	}

	for _, p := range s.collectNotifications(nodes, lookups) {
		s.deliver(p)
	}
}

// deliver builds one notification for a pending delivery and hands it to the
// subscription. It is never called while MonitoredItemService.Mu is held.
//
// Callers are typically the application's ingest goroutine, so this must not
// wait on the subscriber: Subscription.Notify only overwrites the latest value
// for the client handle and wakes run(), which matches the queue size of 1
// advertised in CreateMonitoredItems. A subscriber that is slow, mid-publish or
// already shut down therefore costs the caller nothing.
//
// Two overlapping ChangeNotifications calls for the same node could otherwise
// interleave: caller A reads an older value, caller B reads a newer one and
// stores it first, then A's store overwrites it with the stale value. Holding
// the per-node lock across the read and the store restores the ordering:
// whichever delivery for a node runs last re-reads the live value.
func (s *MonitoredItemService) deliver(p pendingNotification) {
	lock := s.nodeLock(p.node.String())
	lock.Lock()
	defer lock.Unlock()

	val := new(ua.MonitoredItemNotification)
	val.ClientHandle = p.clientHandle
	if p.ns.err != nil {
		if s.SubService.srv.cfg.logger != nil {
			s.SubService.srv.cfg.logger.Warn("error getting namespace %d: %v", p.node.Namespace(), p.ns.err)
		}
		val.Value = &ua.DataValue{}
		val.Value.Status = ua.StatusBad
		val.Value.EncodingMask |= ua.DataValueStatusCode
	} else {
		val.Value = p.ns.ns.Attribute(p.node, p.attributeID)
	}

	p.sub.Notify(val)
}

// collectNotifications is the locked half of ChangeNotifications: it walks the
// monitored-item bookkeeping for every changed node and returns the deliveries
// that implies. Nothing in here may block -- no channel sends, no other locks.
func (s *MonitoredItemService) collectNotifications(nodes []*ua.NodeID, lookups map[uint16]namespaceLookup) []pendingNotification {
	s.Mu.Lock()
	defer s.Mu.Unlock()

	var pending []pendingNotification
	for _, n := range nodes {
		if n == nil {
			continue
		}
		items, ok := s.Nodes[n.String()]
		if !ok {
			// this node isn't monitored - don't have to do anything.
			continue
		}
		for i := range items {
			item := items[i]
			if item == nil {
				continue
			}
			pending = append(pending, pendingNotification{
				sub:          item.Sub,
				clientHandle: item.Req.RequestedParameters.ClientHandle,
				node:         n,
				attributeID:  item.Req.ItemToMonitor.AttributeID,
				ns:           lookups[n.Namespace()],
			})
		}
	}
	return pending
}

func (s *MonitoredItemService) NextID() uint32 {
	i := atomic.AddUint32(&s.id, 1)
	if i == 0 {
		i = atomic.AddUint32(&s.id, 1)
	}
	return i
}

type MonitoredItem struct {
	ID  uint32
	Sub *Subscription
	Req *ua.MonitoredItemCreateRequest

	//TODO: use this
	Mode ua.MonitoringMode
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.2
func (s *MonitoredItemService) CreateMonitoredItems(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.CreateMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()

	count := len(req.ItemsToCreate)

	res := make([]*ua.MonitoredItemCreateResult, count)

	subID := req.SubscriptionID
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Creating monitored items for sub #%d", subID)
	}
	s.SubService.Mu.Lock()
	sub, ok := s.SubService.Subs[subID]
	s.SubService.Mu.Unlock()
	if !ok {
		return nil, errors.New("sub doesn't exist")
	}

	sess := s.SubService.srv.Session(req.RequestHeader)
	if sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
		return nil, errors.New("not your subscription, bro")
	}

	for i := range req.ItemsToCreate {
		itemreq := req.ItemsToCreate[i]
		nodeid := itemreq.ItemToMonitor.NodeID
		item := MonitoredItem{
			ID:  s.NextID(),
			Sub: sub,
			Req: itemreq,
		}

		// book keeping of the new item
		s.Items[item.ID] = &item
		list, ok := s.Nodes[item.Req.ItemToMonitor.NodeID.String()]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.Nodes[item.Req.ItemToMonitor.NodeID.String()] = append(list, &item)

		list, ok = s.Subs[item.Sub.ID]
		if !ok {
			list = make([]*MonitoredItem, 0, 1)
		}
		s.Subs[item.Sub.ID] = append(list, &item)

		if s.SubService.srv.cfg.logger != nil {
			s.SubService.srv.cfg.logger.Debug("Adding monitored item '%s' to sub #%d as %d->%d",
				nodeid.String(),
				subID,
				item.ID,
				itemreq.RequestedParameters.ClientHandle)
		}
		res[i] = &ua.MonitoredItemCreateResult{
			StatusCode:              ua.StatusOK,
			MonitoredItemID:         item.ID,
			RevisedSamplingInterval: sub.RevisedPublishingInterval,
			RevisedQueueSize:        1,
			FilterResult:            ua.NewExtensionObject(nil),
		}
		// do an initial update for the nodeids in the background.
		// These lock the mutex so we can't do them inline here.
		// This will cause them to happen once we unlock.
		go s.ChangeNotification(nodeid)

	}

	resp := &ua.CreateMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         res,                    //                  []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, //          []*DiagnosticInfo
	}

	return resp, nil

}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.3
func (s *MonitoredItemService) ModifyMonitoredItems(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.ModifyMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.4
func (s *MonitoredItemService) SetMonitoringMode(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.SetMonitoringModeRequest](r)
	if err != nil {
		return nil, err
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))

	sess := s.SubService.srv.Session(req.RequestHeader)

	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]

		if item.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
		}

		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
			continue
		}
		item.Mode = req.MonitoringMode
		results[i] = ua.StatusOK
	}

	return &ua.SetMonitoringModeResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}, nil

}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.5
func (s *MonitoredItemService) SetTriggering(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.SetTriggeringRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.12.6
func (s *MonitoredItemService) DeleteMonitoredItems(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.SubService.srv.cfg.logger != nil {
		s.SubService.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.DeleteMonitoredItemsRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	sess := s.SubService.srv.Session(req.RequestHeader)

	results := make([]ua.StatusCode, len(req.MonitoredItemIDs))
	for i := range req.MonitoredItemIDs {
		id := req.MonitoredItemIDs[i]
		item, ok := s.Items[id]
		if !ok {
			results[i] = ua.StatusBadMonitoredItemIDInvalid
		}

		if item.Sub.Session.AuthTokenID.String() != sess.AuthTokenID.String() {
			results[i] = ua.StatusBadSessionIDInvalid
		}

		// this function gets the lock so we need to do it in the background so it can happen after our lock is released.
		go s.DeleteMonitoredItem(id)
		results[i] = ua.StatusOK
	}

	response := &ua.DeleteMonitoredItemsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	return response, nil

}
