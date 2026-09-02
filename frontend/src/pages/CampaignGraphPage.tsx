// SentinelTrace Frontend — Campaign Graph Page

import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Network, ZoomIn, ZoomOut, RefreshCw, Info } from 'lucide-react';
import { useCampaignGraph } from '@/api/hooks';
import { cn } from '@/utils';

export function CampaignGraphPage() {
  const [searchParams] = useSearchParams();
  const analysisId = searchParams.get('analysis_id') || undefined;
  const [depth, setDepth] = useState(2);

  const { data, isLoading, refetch } = useCampaignGraph({
    analysis_id: analysisId,
    depth,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-[hsl(var(--foreground))]">Campaign Graph</h1>
          <p className="text-sm text-[hsl(var(--foreground-muted))] mt-0.5">
            Entity relationship graph for campaign correlation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="text-xs text-[hsl(var(--foreground-muted))]">Depth:</label>
            {[1, 2, 3, 4].map((d) => (
              <button
                key={d}
                onClick={() => setDepth(d)}
                className={cn(
                  'w-7 h-7 rounded text-xs font-medium transition-colors',
                  depth === d
                    ? 'bg-[hsl(var(--accent))] text-[hsl(var(--accent-foreground))]'
                    : 'bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] border border-[hsl(var(--border))] hover:bg-[hsl(var(--surface-3))]'
                )}
              >
                {d}
              </button>
            ))}
          </div>
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="p-2 rounded hover:bg-[hsl(var(--surface-2))] text-[hsl(var(--foreground-muted))] transition-colors"
          >
            <RefreshCw className={cn('w-4 h-4', isLoading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* Stats */}
      {data && (
        <div className="flex items-center gap-4 flex-wrap">
          {[
            { label: 'Nodes', value: data.nodes.length },
            { label: 'Edges', value: data.edges.length },
            { label: 'Emails', value: data.analysis_count },
          ].map(({ label, value }) => (
            <div key={label} className="flex items-center gap-2 text-sm">
              <span className="text-[hsl(var(--foreground-subtle))]">{label}:</span>
              <span className="font-semibold text-[hsl(var(--foreground))]">{value}</span>
            </div>
          ))}
        </div>
      )}

      {/* Legend */}
      <div className="flex items-center gap-4 flex-wrap">
        {[
          { type: 'Email', color: 'hsl(192, 90%, 45%)' },
          { type: 'Sender', color: 'hsl(142, 60%, 45%)' },
          { type: 'Domain', color: 'hsl(270, 70%, 60%)' },
          { type: 'IPAddress', color: 'hsl(25, 90%, 52%)' },
          { type: 'IOC', color: 'hsl(0, 80%, 55%)' },
        ].map(({ type, color }) => (
          <div key={type} className="flex items-center gap-1.5 text-xs text-[hsl(var(--foreground-muted))]">
            <span className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
            {type}
          </div>
        ))}
      </div>

      {/* Graph Canvas */}
      <div className="card-surface h-[600px] relative overflow-hidden rounded-lg">
        {isLoading ? (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="flex flex-col items-center gap-3">
              <RefreshCw className="w-8 h-8 text-[hsl(var(--accent))] animate-spin" />
              <p className="text-sm text-[hsl(var(--foreground-muted))]">Loading graph…</p>
            </div>
          </div>
        ) : !data || data.nodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-4">
            <Network className="w-12 h-12 text-[hsl(var(--foreground-subtle))]" />
            <p className="text-sm text-[hsl(var(--foreground-muted))]">
              {analysisId ? 'No graph data for this analysis yet' : 'Select an analysis to view its campaign graph'}
            </p>
            <div className="flex items-center gap-2 text-xs text-[hsl(var(--foreground-subtle))]">
              <Info className="w-3.5 h-3.5" />
              Graph data is populated after email analysis completes
            </div>
          </div>
        ) : (
          <GraphVisualization nodes={data.nodes} edges={data.edges} />
        )}
      </div>
    </div>
  );
}

// ── Force-Directed Graph ──────────────────────────────────────────────────────

interface GraphNode {
  id: string;
  node_type: string;
  label: string;
  properties: Record<string, unknown>;
}

interface GraphEdge {
  source: string;
  target: string;
  relationship_type: string;
}

function GraphVisualization({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [ForceGraph, setForceGraph] = useState<any>(null);

  useEffect(() => {
    import('react-force-graph-2d').then((m) => setForceGraph(() => m.default));
  }, []);

  const NODE_COLORS: Record<string, string> = {
    Email: 'hsl(192, 90%, 45%)',
    Sender: 'hsl(142, 60%, 45%)',
    Domain: 'hsl(270, 70%, 60%)',
    IPAddress: 'hsl(25, 90%, 52%)',
    IOC: 'hsl(0, 80%, 55%)',
  };

  const graphData = {
    nodes: nodes.map((n) => ({
      id: n.id,
      name: n.label,
      nodeType: n.node_type,
      color: NODE_COLORS[n.node_type] || 'hsl(215, 15%, 60%)',
    })),
    links: edges.map((e) => ({
      source: e.source,
      target: e.target,
      label: e.relationship_type,
    })),
  };

  if (!ForceGraph) {
    return (
      <div className="absolute inset-0 flex items-center justify-center">
        <RefreshCw className="w-6 h-6 text-[hsl(var(--accent))] animate-spin" />
      </div>
    );
  }

  return (
    <ForceGraph
      ref={containerRef}
      graphData={graphData}
      nodeLabel="name"
      nodeColor={(node: any) => node.color}
      linkLabel="label"
      backgroundColor="hsl(222, 20%, 8%)"
      linkColor={() => 'hsl(222, 14%, 25%)'}
      nodeRelSize={5}
      linkDirectionalArrowLength={4}
      linkDirectionalArrowRelPos={1}
      width={containerRef.current?.clientWidth}
      height={600}
    />
  );
}
