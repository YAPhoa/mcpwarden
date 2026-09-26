//go:build flowtest

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The browser owner flows need tools on a vault connector before setup
// discovery (roadmap step 5) exists. This route stores the given tool list as
// the connector's cached discovery and publishes it, as a completed discovery
// would. It never dials the upstream. Remove it when setup discovery lands.
func init() {
	testRoutes = func(mux *http.ServeMux, rs *runtimes, protect func(http.Handler) http.Handler) {
		mux.Handle("/api/test/discovery/", protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			name := strings.TrimPrefix(r.URL.Path, "/api/test/discovery/")
			var tools []*mcp.Tool
			if r.Method != http.MethodPut || rs.store == nil || json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&tools) != nil {
				http.Error(w, "invalid test discovery", http.StatusBadRequest)
				return
			}
			owner := requestOwner(r)
			rs.mu.Lock()
			defer rs.mu.Unlock()
			rt := rs.getLocked(owner)
			if err := rs.store.SetDiscovery(owner, name, tools); err != nil {
				http.Error(w, "could not store discovery", http.StatusBadRequest)
				return
			}
			rt.proxy.Changed(name, tools, true)
			rt.proxy.Changed(name, nil, false)
			w.WriteHeader(http.StatusNoContent)
		})))
	}
}
