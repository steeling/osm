package ads

// Liveness is the Kubernetes liveness probe handler.
func (s *Server) Liveness() bool {
	return true
}

// Readiness is the Kubernetes readiness probe handler.
func (s *Server) Readiness() bool {
	return true
}

// GetID returns the ID of the probe
func (s *Server) GetID() string {
	return ServerType
}
