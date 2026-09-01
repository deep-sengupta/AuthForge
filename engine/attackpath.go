package engine

import "fmt"

func BuildAttackPaths(findings []Finding) []AttackPath {
	out := make([]AttackPath, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		id := "path:" + f.ID
		*f = attachPathID(*f, id)
		out = append(out, AttackPath{ID: id, FindingID: f.ID, Steps: append([]string(nil), f.ExploitChain...), Verified: f.Verified, Confidence: f.Confidence})
	}
	return out
}

func attachPathID(f Finding, id string) Finding { f.AttackPathID = id; return f }

func AddFindingPaths(g AuthorizationGraph, findings []Finding) AuthorizationGraph {
	nodeSeen := map[string]bool{}
	for _, n := range g.Nodes {
		nodeSeen[n.ID] = true
	}
	edgeSeen := map[string]bool{}
	for _, e := range g.Edges {
		edgeSeen[e.From+"|"+e.To+"|"+e.Relation] = true
	}
	for _, f := range findings {
		fid := "finding:" + f.ID
		if !nodeSeen[fid] {
			g.Nodes = append(g.Nodes, GraphNode{ID: fid, Type: "finding", Label: fmt.Sprintf("%s [%d%%]", f.Title, f.Confidence)})
			nodeSeen[fid] = true
		}
		prev := fid
		for i, step := range f.ExploitChain {
			sid := fmt.Sprintf("pathstep:%s:%d", f.ID, i)
			if !nodeSeen[sid] {
				g.Nodes = append(g.Nodes, GraphNode{ID: sid, Type: "attack-step", Label: step})
				nodeSeen[sid] = true
			}
			k := prev + "|" + sid + "|attack-step"
			if !edgeSeen[k] {
				g.Edges = append(g.Edges, GraphEdge{From: prev, To: sid, Relation: "attack-step", Allowed: nil})
				edgeSeen[k] = true
			}
			prev = sid
		}
	}
	return g
}
