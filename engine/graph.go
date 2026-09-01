package engine

import (
	"fmt"
	"sort"
	"strings"
)

func BuildGraph(obs []Observation) AuthorizationGraph {
	nodes := map[string]GraphNode{}
	edges := map[string]GraphEdge{}
	addNode := func(id, t, l string) { nodes[id] = GraphNode{ID: id, Type: t, Label: safe(l)} }
	for _, o := range obs {
		role := "role:" + safe(o.Actor.Role)
		user := "user:" + safe(o.Actor.User)
		tenant := "tenant:" + safe(o.Actor.Tenant)
		ep := "endpoint:" + safe(o.Method+":"+o.Endpoint)
		action := "action:" + safe(o.Action)
		addNode(role, "role", o.Actor.Role)
		addNode(user, "user", o.Actor.User)
		if o.Actor.Tenant != "" {
			addNode(tenant, "tenant", o.Actor.Tenant)
		}
		addNode(ep, "endpoint", o.Method+" "+o.Endpoint)
		addNode(action, "action", o.Action)
		edges[user+"->"+role] = GraphEdge{From: user, To: role, Relation: "has-role"}
		if o.Actor.Tenant != "" {
			edges[user+"->"+tenant] = GraphEdge{From: user, To: tenant, Relation: "belongs-to"}
		}
		edges[edgeKey(role+"->"+ep, "may-access", o.Allowed)] = GraphEdge{From: role, To: ep, Relation: "may-access", Allowed: o.Allowed}
		edges[ep+"->"+action] = GraphEdge{From: ep, To: action, Relation: "performs"}
		for _, obj := range o.Objects {
			oid := "object:" + safe(obj.Value)
			addNode(oid, "object", obj.Value)
			edges[edgeKey(user+"->"+oid, "observed-access", o.Allowed)] = GraphEdge{From: user, To: oid, Relation: "observed-access", Allowed: o.Allowed}
			edges[ep+"->"+oid] = GraphEdge{From: ep, To: oid, Relation: "references"}
		}
	}
	nl := make([]GraphNode, 0, len(nodes))
	for _, n := range nodes {
		nl = append(nl, n)
	}
	sort.Slice(nl, func(i, j int) bool { return nl[i].ID < nl[j].ID })
	el := make([]GraphEdge, 0, len(edges))
	for _, e := range edges {
		el = append(el, e)
	}
	sort.Slice(el, func(i, j int) bool {
		return fmt.Sprintf("%s%s", el[i].From, el[i].To) < fmt.Sprintf("%s%s", el[j].From, el[j].To)
	})
	return AuthorizationGraph{Nodes: nl, Edges: el}
}

func safe(s string) string {
	return strings.NewReplacer("\"", "'", "\n", " ", "\r", " ").Replace(s)
}

func edgeKey(base, relation string, allowed *bool) string {
	state := "unknown"
	if allowed != nil {
		if *allowed {
			state = "allowed"
		} else {
			state = "denied"
		}
	}
	return base + "|" + relation + "|" + state
}
