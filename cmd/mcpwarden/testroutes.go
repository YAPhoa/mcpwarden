package main

import "net/http"

// testRoutes is set only in binaries built with the flowtest tag, for the
// browser owner flows. Release builds never register it.
var testRoutes func(mux *http.ServeMux, rs *runtimes, protect func(http.Handler) http.Handler)
