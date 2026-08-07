package server

import (
	"strings"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

// DiscoveryService implements the Discovery Service Set
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4
type DiscoveryService struct {
	srv *Server
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.2
func (s *DiscoveryService) FindServers(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:           "find_servers_request",
		ServiceType:     "FindServers",
		RequestID:       reqID,
		SecureChannelID: secureChannelID(sc),
		RemoteAddr:      remoteAddr(sc),
	})

	req, err := safeReq[*ua.FindServersRequest](r)
	if err != nil {
		return nil, err
	}

	response := &ua.FindServersResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Servers: []*ua.ApplicationDescription{
			s.srv.Endpoints()[0].Server,
		},
	}
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:           "find_servers_response",
		ServiceType:     "FindServers",
		RequestID:       reqID,
		SecureChannelID: secureChannelID(sc),
		RemoteAddr:      remoteAddr(sc),
	})

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.3
func (s *DiscoveryService) FindServersOnNetwork(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.FindServersOnNetworkRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.4
func (s *DiscoveryService) GetEndpoints(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.GetEndpointsRequest](r)
	if err != nil {
		return nil, err
	}
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:           "get_endpoints_request",
		ServiceType:     "GetEndpoints",
		RequestID:       reqID,
		SecureChannelID: secureChannelID(sc),
		RemoteAddr:      remoteAddr(sc),
		EndpointURL:     req.EndpointURL,
	})

	requrl := strings.ToLower(req.EndpointURL)
	matching_endpoints := make([]*ua.EndpointDescription, 0)
	for i := range s.srv.endpoints {
		ep := s.srv.endpoints[i]
		if strings.ToLower(ep.EndpointURL) == requrl {
			matching_endpoints = append(matching_endpoints, ep)
		}
	}

	response := &ua.GetEndpointsResponse{
		ResponseHeader: responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Endpoints:      matching_endpoints,
	}
	matchedCount := len(matching_endpoints)
	emitDiagInfo(s.srv.cfg.logger, diagPayload{
		Event:                "get_endpoints_response",
		ServiceType:          "GetEndpoints",
		RequestID:            reqID,
		SecureChannelID:      secureChannelID(sc),
		RemoteAddr:           remoteAddr(sc),
		EndpointURL:          req.EndpointURL,
		MatchedEndpointCount: &matchedCount,
	})

	return response, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.5
func (s *DiscoveryService) RegisterServer(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.RegisterServerRequest](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.4.6
func (s *DiscoveryService) RegisterServer2(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.RegisterServer2Request](r)
	if err != nil {
		return nil, err
	}
	return serviceUnsupported(req.RequestHeader), nil
}
