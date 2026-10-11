package target

// CountHosts returns how many hosts Hosts(locals) would produce, without
// expanding them.
func CountHosts(locals []Local) uint64 {
	spans := make([]span, 0, len(locals))
	for _, l := range locals {
		spans = append(spans, prefixSpan(l.Prefix))
	}
	return countSpans(mergeSpans(spans))
}
