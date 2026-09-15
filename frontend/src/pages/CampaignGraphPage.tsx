// SentinelTrace Frontend — Campaign Graph Page with 3D Radial Node Rendering, Connected Link Highlighting & Enhanced Analyst Exercises

import { useEffect, useRef, useState, useMemo } from 'react';
import { useSearchParams } from 'react-router-dom';
import {
  Network, ZoomIn, ZoomOut, RefreshCw, ChevronDown, ChevronUp, ChevronLeft, ChevronRight,
  Search, Download, Maximize2, X, Key, Radio, Mail, Globe, Server, FileText,
  Target, Compass, Layers, CheckCircle2, ArrowRight, Shield, Zap, Info
} from 'lucide-react';
import { useCampaignGraph, useWorkspaceEmails } from '@/api/hooks';
import { cn } from '@/utils';
import { useWorkspaceStore } from '@/store/workspace';
import ForceGraph2D from 'react-force-graph-2d';
import { CampaignInvestigationPanel } from '@/components/campaign/CampaignInvestigationPanel';

const NODE_COLORS: Record<string, string> = {
  Email: '#3b82f6',
  Sender: '#22c55e',
  Domain: '#a855f7',
  IPAddress: '#f97316',
  IOC: '#ef4444',
  Attachment: '#eab308',
  ThreatActor: '#f97316',
};

const BASE_RADIUS: Record<string, number> = {
  Email: 10,
  Sender: 9,
  Domain: 9,
  IPAddress: 9,
  IOC: 8,
  Attachment: 8,
  ThreatActor: 13,
};

export function CampaignGraphPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialAnalysisId = searchParams.get('analysis_id') || '';
  const campaignId = searchParams.get('campaign_id') || undefined;

  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string>(initialAnalysisId);
  const [nodeSearchQuery, setNodeSearchQuery] = useState<string>('');
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [hoveredNode, setHoveredNode] = useState<any>(null);
  const [depth, setDepth] = useState(2);
  const [activeTab, setActiveTab] = useState<'campaign' | 'exercises'>('campaign');
  const [completedExercises, setCompletedExercises] = useState<Record<number, boolean>>({});

  const [visibleTypes, setVisibleTypes] = useState<Record<string, boolean>>({
    Email: true,
    Sender: true,
    Domain: true,
    IPAddress: true,
    IOC: true,
    Attachment: true,
    ThreatActor: true,
  });

  const fgRef = useRef<any>(null);

  const { currentWorkspaceId } = useWorkspaceStore();
  const { data: emailsData } = useWorkspaceEmails(currentWorkspaceId, { page: 1, page_size: 50 });
  const emails = emailsData?.items || [];

  const { data, isLoading, error, refetch } = useCampaignGraph(currentWorkspaceId, {
    analysis_id: selectedAnalysisId || undefined,
    campaign_id: campaignId,
    depth,
  });

  // Calculate raw nodes & links strictly from backend workspace data
  const rawGraphData = useMemo(() => {
    if (data && data.nodes && data.nodes.length > 0) {
      let activeNodes = data.nodes;
      if (depth === 1) {
        activeNodes = data.nodes.filter(n => (n.node_type || (n as any).nodeType) === 'Email' || (n.node_type || (n as any).nodeType) === 'Domain');
      } else if (depth === 2) {
        activeNodes = data.nodes.filter(n => (n.node_type || (n as any).nodeType) === 'Email' || (n.node_type || (n as any).nodeType) === 'Domain' || (n.node_type || (n as any).nodeType) === 'IPAddress');
      }

      const nodeIds = new Set(activeNodes.map(n => n.id));
      const activeEdges = (data.edges || []).filter(e => nodeIds.has(e.source) && nodeIds.has(e.target));

      return {
        nodes: activeNodes.map(n => ({
          id: n.id,
          name: n.label || n.id,
          val: BASE_RADIUS[n.node_type || (n as any).nodeType] || 9,
          color: NODE_COLORS[n.node_type || (n as any).nodeType] || '#3b82f6',
          nodeType: n.node_type || (n as any).nodeType || 'Domain',
          properties: n.properties || {},
        })),
        links: activeEdges.map(e => ({
          source: e.source,
          target: e.target,
          label: e.relationship_type || (e as any).label || 'CONNECTED',
        })),
      };
    }

    return { nodes: [], links: [] };
  }, [data, depth]);

  // Filtered Graph Data by Type & Search Query
  const filteredGraphData = useMemo(() => {
    const query = nodeSearchQuery.toLowerCase().trim();

    const nodes = rawGraphData.nodes.filter((n) => {
      const type = n.nodeType;
      if (visibleTypes[type] === false) return false;
      if (!query) return true;
      return (n.name || '').toLowerCase().includes(query) || (n.id || '').toLowerCase().includes(query);
    });

    const nodeIds = new Set(nodes.map((n) => n.id));
    const links = rawGraphData.links.filter(
      (l: any) =>
        nodeIds.has(typeof l.source === 'object' ? l.source.id : l.source) &&
        nodeIds.has(typeof l.target === 'object' ? l.target.id : l.target)
    );

    return { nodes, links };
  }, [rawGraphData, visibleTypes, nodeSearchQuery]);

  // Configure physics forces
  useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge')?.strength(-450);
      fgRef.current.d3Force('link')?.distance(110);
    }
  }, [filteredGraphData]);

  // Active node being inspected (selected click takes priority over mouse hover)
  const activeNode = selectedNode || hoveredNode;

  // Compute connected nodes & links set for activeNode highlighting
  const { connectedNodeIds, connectedLinkSet } = useMemo(() => {
    const nodes = new Set<string>();
    const links = new Set<any>();
    if (activeNode) {
      nodes.add(activeNode.id);
      filteredGraphData.links.forEach((l: any) => {
        const sId = typeof l.source === 'object' ? l.source.id : l.source;
        const tId = typeof l.target === 'object' ? l.target.id : l.target;
        if (sId === activeNode.id || tId === activeNode.id) {
          nodes.add(sId);
          nodes.add(tId);
          links.add(l);
        }
      });
    }
    return { connectedNodeIds: nodes, connectedLinkSet: links };
  }, [activeNode, filteredGraphData.links]);

  // Counts summary
  const artifactComposition = useMemo(() => {
    const counts = { domainCount: 0, ipCount: 0, hashCount: 0, emailCount: 0 };
    rawGraphData.nodes.forEach(n => {
      if (n.nodeType === 'Domain') counts.domainCount++;
      else if (n.nodeType === 'IPAddress') counts.ipCount++;
      else if (n.nodeType === 'Attachment' || n.nodeType === 'IOC') counts.hashCount++;
      else if (n.nodeType === 'Email' || n.nodeType === 'Sender') counts.emailCount++;
    });
    return counts;
  }, [rawGraphData]);

  const toggleType = (type: string) => {
    setVisibleTypes((prev) => ({ ...prev, [type]: !prev[type] }));
  };

  const handleZoomIn = () => {
    if (fgRef.current) fgRef.current.zoom(fgRef.current.zoom() * 1.3, 300);
  };

  const handleZoomOut = () => {
    if (fgRef.current) fgRef.current.zoom(fgRef.current.zoom() / 1.3, 300);
  };

  const handleZoomReset = () => {
    if (fgRef.current) fgRef.current.zoomToFit(400, 50);
  };

  const handlePanUp = () => {
    if (fgRef.current) {
      const pos = fgRef.current.centerAt();
      const zoom = fgRef.current.zoom() || 1;
      const step = 120 / zoom;
      fgRef.current.centerAt(pos ? pos.x : 0, (pos ? pos.y : 0) - step, 300);
    }
  };

  const handlePanDown = () => {
    if (fgRef.current) {
      const pos = fgRef.current.centerAt();
      const zoom = fgRef.current.zoom() || 1;
      const step = 120 / zoom;
      fgRef.current.centerAt(pos ? pos.x : 0, (pos ? pos.y : 0) + step, 300);
    }
  };

  const handlePanLeft = () => {
    if (fgRef.current) {
      const pos = fgRef.current.centerAt();
      const zoom = fgRef.current.zoom() || 1;
      const step = 120 / zoom;
      fgRef.current.centerAt((pos ? pos.x : 0) - step, pos ? pos.y : 0, 300);
    }
  };

  const handlePanRight = () => {
    if (fgRef.current) {
      const pos = fgRef.current.centerAt();
      const zoom = fgRef.current.zoom() || 1;
      const step = 120 / zoom;
      fgRef.current.centerAt((pos ? pos.x : 0) + step, pos ? pos.y : 0, 300);
    }
  };

  const handleExportGraph = () => {
    const jsonStr = JSON.stringify(filteredGraphData, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `sentineltrace-campaign-graph-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  // Focus specific node for exercises
  const focusNodeById = (nodeId: string, stepIndex?: number) => {
    const node: any = filteredGraphData.nodes.find(n => n.id.toLowerCase().includes(nodeId.toLowerCase()))
      || rawGraphData.nodes.find(n => n.id.toLowerCase().includes(nodeId.toLowerCase()));
    
    if (stepIndex !== undefined) {
      setCompletedExercises(prev => ({ ...prev, [stepIndex]: true }));
    }

    if (node) {
      setSelectedNode(node);
      // Switch to campaign tab so the node detail panel shows
      setActiveTab('campaign');
      
      const doFocus = () => {
        if (fgRef.current) {
          // Get the live node (with updated x/y from physics)
          const liveNode: any = (fgRef.current as any).graphData?.()?.nodes?.find((n: any) => n.id === node.id) || node;
          if (liveNode.x != null && liveNode.y != null && Number.isFinite(liveNode.x) && Number.isFinite(liveNode.y)) {
            fgRef.current.centerAt(liveNode.x, liveNode.y, 500);
            fgRef.current.zoom(3.0, 500);
          } else {
            // Physics not settled yet — retry after a short delay
            setTimeout(() => {
              const retryNode: any = (fgRef.current as any)?.graphData?.()?.nodes?.find((n: any) => n.id === node.id) || node;
              if (fgRef.current && retryNode.x != null && Number.isFinite(retryNode.x)) {
                fgRef.current.centerAt(retryNode.x, retryNode.y, 500);
                fgRef.current.zoom(3.0, 500);
              } else if (fgRef.current) {
                // Final fallback: just zoom in at center
                fgRef.current.zoomToFit(400, 80);
              }
            }, 800);
          }
        }
      };
      doFocus();
    } else {
      // Node not found in current graph — it may be filtered by depth or type; alert user
      console.warn(`Node "${nodeId}" not found in current graph. Try increasing the depth level.`);
    }
  };


  return (
    <div className="flex flex-col h-[calc(100dvh-7rem)] lg:h-[calc(100vh-6rem)] space-y-4 max-w-[1600px] mx-auto">
      {/* ── Page Header & Controls Toolbar ──────────────────────────────── */}
      <div className="bg-[#121824] border border-[#232e42] rounded p-4 space-y-3">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-white flex items-center gap-2.5 tracking-tight">
              <Network className="w-5 h-5 text-[#3b82f6]" />
              Campaign Correlation Knowledge Graph
            </h1>
            <p className="text-xs text-[#94a3b8] mt-0.5 font-mono">
              Hover or click any node to trace connected relationships & inspect telemetry in the side column.
            </p>
          </div>

          {/* Action Buttons & Focus Selector */}
          <div className="flex items-center gap-3 flex-wrap">
            {/* Target Artifact Selector */}
            {emails.length > 0 && (
              <div className="relative min-w-[200px]">
                <select
                  value={selectedAnalysisId}
                  onChange={(e) => {
                    const val = e.target.value;
                    setSelectedAnalysisId(val);
                    setSearchParams(val ? { analysis_id: val } : {});
                  }}
                  className="w-full appearance-none px-3 py-1.5 bg-[#090d16] border border-[#232e42] rounded text-xs text-white pr-8 focus:border-[#3b82f6] outline-none font-mono truncate cursor-pointer"
                >
                  <option value="">🌐 All Correlated Artifacts</option>
                  {emails.map((e) => (
                    <option key={e.id} value={e.id}>
                      ✉️ {e.subject || '(no subject)'}
                    </option>
                  ))}
                </select>
                <ChevronDown className="w-3.5 h-3.5 absolute right-2.5 top-1/2 -translate-y-1/2 text-[#64748b] pointer-events-none" />
              </div>
            )}

            {/* Depth Selector */}
            <div className="flex items-center gap-1 bg-[#090d16] border border-[#232e42] rounded p-1 text-xs font-mono">
              <span className="px-1.5 text-[10px] text-[#64748b] uppercase">Depth:</span>
              {[1, 2, 3, 4].map((d) => (
                <button
                  key={d}
                  onClick={() => setDepth(d)}
                  className={cn(
                    'w-6 h-6 rounded text-xs font-bold transition-colors cursor-pointer',
                    depth === d
                      ? 'bg-[#2563eb] text-white'
                      : 'text-[#94a3b8] hover:bg-[#161c2b]'
                  )}
                >
                  {d}
                </button>
              ))}
            </div>

            {/* Mode Switcher */}
            <div className="flex items-center gap-1 bg-[#090d16] border border-[#232e42] rounded p-1 text-xs font-mono">
              <button
                onClick={() => setActiveTab('campaign')}
                className={cn(
                  'px-2.5 py-1 rounded text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5',
                  activeTab === 'campaign'
                    ? 'bg-[#2563eb] text-white'
                    : 'text-[#94a3b8] hover:text-white'
                )}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Campaign</span>
              </button>
              <button
                onClick={() => setActiveTab('exercises')}
                className={cn(
                  'px-2.5 py-1 rounded text-xs font-bold transition-colors cursor-pointer flex items-center gap-1.5',
                  activeTab === 'exercises'
                    ? 'bg-[#f97316] text-white'
                    : 'text-[#94a3b8] hover:text-white'
                )}
              >
                <Compass className="w-3.5 h-3.5" />
                <span>Analyst Exercises</span>
              </button>
            </div>

            <button
              onClick={handleExportGraph}
              className="p-1.5 bg-[#090d16] border border-[#232e42] rounded text-[#94a3b8] hover:text-white transition-colors cursor-pointer"
              title="Export Graph JSON"
            >
              <Download className="w-4 h-4" />
            </button>

            <button
              onClick={() => refetch()}
              disabled={isLoading}
              className="p-1.5 bg-[#090d16] border border-[#232e42] rounded text-[#94a3b8] hover:text-white transition-colors cursor-pointer"
              title="Refresh Graph"
            >
              <RefreshCw className={cn('w-4 h-4', isLoading && 'animate-spin')} />
            </button>
          </div>
        </div>

        {/* ── Search & Entity Filter Bar ─────────────────────────────────── */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#232e42]">
          {/* Node Search Bar */}
          <div className="relative w-full sm:w-72">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#64748b]" />
            <input
              type="text"
              placeholder="Search graph entities..."
              value={nodeSearchQuery}
              onChange={(e) => setNodeSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1 bg-[#090d16] border border-[#232e42] rounded text-xs text-white placeholder-[#64748b] outline-none focus:border-[#3b82f6] font-mono"
            />
          </div>

          {/* Type Filter Toggles */}
          <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
            {Object.keys(NODE_COLORS).map((type) => {
              const active = visibleTypes[type] !== false;
              const color = NODE_COLORS[type];
              return (
                <button
                  key={type}
                  onClick={() => toggleType(type)}
                  className={cn(
                    'px-2.5 py-1 rounded border text-[11px] font-semibold flex items-center gap-1.5 transition-colors cursor-pointer',
                    active
                      ? 'bg-[#161c2b] border-[#3b82f6]/40 text-white'
                      : 'bg-[#090d16] border-[#232e42] text-[#64748b] line-through'
                  )}
                >
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                  <span>{type}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* ── Main Canvas & Right Side Column ─────────────────────────────── */}
      <div className="relative flex-1 w-full flex flex-col lg:flex-row bg-[#090d16] border border-[#232e42] rounded overflow-hidden min-h-0">
        {/* Left Canvas Area (High Quality 3D Radial Balls + Relationship Label Canvas) */}
        <div className="relative w-full h-[45vh] lg:flex-1 lg:h-full touch-none select-none overflow-hidden shrink-0">
          {/* Top-Left Controls Toolbar (Zoom & Up/Down/Left/Right Directional Pan) */}
          <div className="absolute top-4 left-4 z-10 flex flex-col bg-[#121824]/95 backdrop-blur border border-[#232e42] rounded-lg p-1.5 shadow-xl gap-1.5">
            {/* Zoom Controls */}
            <div className="flex items-center gap-1 border-b border-[#232e42] pb-1.5">
              <button
                onClick={handleZoomIn}
                className="p-1.5 hover:bg-[#161c2b] text-[#94a3b8] hover:text-white rounded transition-colors cursor-pointer"
                title="Zoom In (+)"
              >
                <ZoomIn className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomOut}
                className="p-1.5 hover:bg-[#161c2b] text-[#94a3b8] hover:text-white rounded transition-colors cursor-pointer"
                title="Zoom Out (-)"
              >
                <ZoomOut className="w-4 h-4" />
              </button>
              <button
                onClick={handleZoomReset}
                className="p-1.5 hover:bg-[#161c2b] text-[#94a3b8] hover:text-white rounded transition-colors cursor-pointer"
                title="Fit View"
              >
                <Maximize2 className="w-4 h-4" />
              </button>
            </div>

            {/* Directional Panning Controls (Up, Down, Left, Right) */}
            <div className="flex flex-col items-center gap-1 pt-0.5">
              <button
                onClick={handlePanUp}
                className="p-1.5 bg-[#090d16] hover:bg-[#1d283a] text-[#3b82f6] hover:text-white rounded border border-[#232e42] transition-colors cursor-pointer flex items-center justify-center font-bold"
                title="Pan Graph Up"
              >
                <ChevronUp className="w-4 h-4" />
              </button>

              <div className="flex items-center gap-1">
                <button
                  onClick={handlePanLeft}
                  className="p-1.5 bg-[#090d16] hover:bg-[#1d283a] text-[#94a3b8] hover:text-white rounded border border-[#232e42] transition-colors cursor-pointer"
                  title="Pan Graph Left"
                >
                  <ChevronLeft className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={handlePanRight}
                  className="p-1.5 bg-[#090d16] hover:bg-[#1d283a] text-[#94a3b8] hover:text-white rounded border border-[#232e42] transition-colors cursor-pointer"
                  title="Pan Graph Right"
                >
                  <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>

              <button
                onClick={handlePanDown}
                className="p-1.5 bg-[#090d16] hover:bg-[#1d283a] text-[#3b82f6] hover:text-white rounded border border-[#232e42] transition-colors cursor-pointer flex items-center justify-center font-bold"
                title="Pan Graph Down"
              >
                <ChevronDown className="w-4 h-4" />
              </button>
            </div>
          </div>
          {/* Canvas Render — Empty State or Interactive Force Graph */}
          {isLoading ? (
            <div className="flex flex-col items-center justify-center h-full gap-3 text-center p-6">
              <RefreshCw className="w-8 h-8 text-[#3b82f6] animate-spin" />
              <span className="text-xs text-[#94a3b8] font-mono">Loading campaign correlation graph...</span>
            </div>
          ) : filteredGraphData.nodes.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-4 text-center p-6">
              <div className="w-14 h-14 rounded-2xl bg-[#121824] border border-[#232e42] flex items-center justify-center text-[#3b82f6] shadow-lg">
                <Network className="w-7 h-7" />
              </div>
              <div className="space-y-1.5 max-w-md">
                <h3 className="text-base font-semibold text-white">No Campaign Graph Available</h3>
                <p className="text-xs text-[#94a3b8] leading-relaxed">
                  No correlated email campaigns or threat infrastructure detected in this workspace yet. Upload and analyze emails to automatically construct threat correlation graphs.
                </p>
              </div>
              <button
                onClick={() => window.location.href = '/investigate'}
                className="px-4 py-2 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded transition-colors flex items-center gap-2 cursor-pointer shadow-sm"
              >
                <Mail className="w-4 h-4" />
                <span>Upload & Analyze Email</span>
              </button>
            </div>
          ) : (
            <ForceGraph2D
              ref={fgRef}
              graphData={filteredGraphData}
              backgroundColor="#090d16"
              enableZoomInteraction={true}
              enablePanInteraction={true}
              enablePointerInteraction={true}
              enableNodeDrag={true}
              onBackgroundClick={() => setSelectedNode(null)}
              nodeColor={(node: any) => node.color}
              nodeRelSize={9}
              linkWidth={(link: any) => {
                if (activeNode) {
                  return connectedLinkSet.has(link) ? 3 : 1;
                }
                return 1.5;
              }}
              linkColor={(link: any) => {
                if (activeNode) {
                  return connectedLinkSet.has(link) ? '#3b82f6' : 'rgba(35, 46, 66, 0.2)';
                }
                return '#232e42';
              }}
              linkDirectionalParticles={(link: any) => (activeNode && connectedLinkSet.has(link) ? 4 : 2)}
              linkDirectionalParticleSpeed={0.008}
              linkDirectionalParticleWidth={(link: any) => (activeNode && connectedLinkSet.has(link) ? 3 : 2)}
              linkDirectionalParticleColor={(link: any) => (activeNode && connectedLinkSet.has(link) ? '#3b82f6' : '#f97316')}
              linkLabel={(link: any) => `Relationship: ${link.label}`}
              nodeLabel={(node: any) => `${node.name || node.id} [${node.nodeType}]`}
            
            /* Render Relationship Labels on Links */
            linkCanvasObjectMode={() => 'after'}
            linkCanvasObject={(link: any, ctx, globalScale) => {
              if (!link.label || globalScale < 0.6) return;
              const isConnected = !activeNode || connectedLinkSet.has(link);
              if (!isConnected) return;

              const start = link.source;
              const end = link.target;
              if (typeof start !== 'object' || typeof end !== 'object') return;
              if (!Number.isFinite(start.x) || !Number.isFinite(start.y) || !Number.isFinite(end.x) || !Number.isFinite(end.y)) return;

              const text = link.label;
              const fontSize = 10 / globalScale;
              ctx.font = `${fontSize}px JetBrains Mono, monospace`;

              const x = (start.x + end.x) / 2;
              const y = (start.y + end.y) / 2;
              if (!Number.isFinite(x) || !Number.isFinite(y)) return;

              const textWidth = ctx.measureText(text).width;
              const padding = 4 / globalScale;

              // Dark pill background for relationship label
              ctx.fillStyle = 'rgba(9, 13, 22, 0.9)';
              ctx.strokeStyle = activeNode && connectedLinkSet.has(link) ? '#3b82f6' : '#232e42';
              ctx.lineWidth = 1 / globalScale;
              ctx.beginPath();
              ctx.rect(x - textWidth / 2 - padding, y - fontSize / 2 - padding, textWidth + padding * 2, fontSize + padding * 2);
              ctx.fill();
              ctx.stroke();

              // Relationship Label Text
              ctx.textAlign = 'center';
              ctx.textBaseline = 'middle';
              ctx.fillStyle = activeNode && connectedLinkSet.has(link) ? '#3b82f6' : '#94a3b8';
              ctx.fillText(text, x, y);
            }}

            /* Render 3D High Quality Nodes ("Balls Quality") */
            nodeCanvasObject={(node: any, ctx, globalScale) => {
              if (!node || !Number.isFinite(node.x) || !Number.isFinite(node.y)) return;

              const isSelected = selectedNode && selectedNode.id === node.id;
              const isHovered = hoveredNode && hoveredNode.id === node.id;
              const isDimmed = activeNode && !connectedNodeIds.has(node.id);

              const baseR = BASE_RADIUS[node.nodeType] || 9;
              const radius = isSelected ? baseR + 4 : isHovered ? baseR + 2 : baseR;
              if (!Number.isFinite(radius) || radius <= 0) return;

              // Draw Outer Glow Halo if Active
              if ((isSelected || isHovered) && !isDimmed) {
                ctx.beginPath();
                ctx.arc(node.x, node.y, radius + 5, 0, 2 * Math.PI, false);
                ctx.fillStyle = isSelected ? 'rgba(59, 130, 246, 0.25)' : 'rgba(37, 99, 235, 0.15)';
                ctx.fill();
              }

              // Safe Radial 3D Specular Highlight Fill
              let grad: CanvasGradient | string = node.color || '#3b82f6';
              try {
                const radial = ctx.createRadialGradient(
                  node.x - radius * 0.35,
                  node.y - radius * 0.35,
                  Math.max(0.1, radius * 0.1),
                  node.x,
                  node.y,
                  radius
                );
                if (isDimmed) {
                  radial.addColorStop(0, '#232e42');
                  radial.addColorStop(1, '#090d16');
                } else {
                  radial.addColorStop(0, '#ffffff'); // Center specular shine
                  radial.addColorStop(0.3, node.color || '#3b82f6');
                  radial.addColorStop(1, '#090d16');
                }
                grad = radial;
              } catch (e) {
                grad = node.color || '#3b82f6';
              }

              ctx.beginPath();
              ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
              ctx.fillStyle = grad;
              ctx.fill();

              // Smooth Border Ring
              ctx.strokeStyle = isSelected ? '#ffffff' : isHovered ? '#3b82f6' : isDimmed ? 'rgba(35, 46, 66, 0.3)' : node.color || '#3b82f6';
              ctx.lineWidth = (isSelected ? 2.5 : isHovered ? 2 : 1.2) / globalScale;
              ctx.stroke();
            }}
            onNodeHover={(node) => setHoveredNode(node || null)}
            onNodeClick={(node: any) => {
              setSelectedNode(node);
              if (node && fgRef.current && node.x != null && node.y != null) {
                fgRef.current.centerAt(node.x, node.y, 400);
              }
            }}
          />
        )}
      </div>

        {/* ── Right Side Column (Live Mouse Hover / Selection Telemetry Panel) ── */}
        <div className="w-full lg:w-[380px] bg-[#121824] border-t lg:border-t-0 lg:border-l border-[#232e42] flex-1 lg:h-full flex flex-col z-20 shrink-0 min-h-0">
          
          {/* STATE 1: Mouse Hovered or Clicked Node Inspection */}
          {activeNode ? (
            <div className="flex-1 flex flex-col h-full overflow-hidden">
              <div className="p-4 border-b border-[#232e42] flex items-center justify-between bg-[#161c2b]">
                <div className="flex items-center gap-2.5">
                  <Target className="w-4 h-4 text-[#3b82f6]" />
                  <div>
                    <span className="text-xs font-bold text-white font-mono block">
                      {selectedNode ? 'Node Details & Telemetry' : 'Live Hover Telemetry'}
                    </span>
                    <span className="text-[10px] text-[#94a3b8] font-mono">
                      {selectedNode ? 'Clicked Entity Inspection' : 'Hovering over graph node'}
                    </span>
                  </div>
                </div>
                {selectedNode && (
                  <button
                    onClick={() => setSelectedNode(null)}
                    className="text-[#64748b] hover:text-white p-1 rounded cursor-pointer hover:bg-[#232e42]"
                    title="Clear Selection"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              <div className="flex-1 overflow-y-auto">
                <CampaignInvestigationPanel selectedNode={activeNode} />
              </div>
            </div>
          ) : activeTab === 'exercises' ? (
            /* STATE 2: Enhanced Guided Threat Hunting Exercises */
            <div className="p-5 space-y-5 overflow-y-auto flex-1 font-mono">
              <div className="border-b border-[#232e42] pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-[#f97316] uppercase tracking-wider block">
                    ANALYST EXERCISES
                  </span>
                  <span className="text-[11px] text-[#22c55e] font-bold">
                    {Object.keys(completedExercises).length} / 4 Completed
                  </span>
                </div>
                <h2 className="text-lg font-bold text-white tracking-tight mt-0.5">
                  Guided Threat Hunt
                </h2>
                <p className="text-xs text-[#94a3b8] mt-1 font-sans">
                  Touch or click tasks below to highlight nodes and trace campaign connections.
                </p>
              </div>

              <div className="space-y-4">
                {/* Exercise 1 */}
                <div className={cn(
                  "bg-[#090d16] border rounded p-4 space-y-3 transition-colors",
                  completedExercises[1] ? "border-[#22c55e]/50 bg-[#22c55e]/5" : "border-[#232e42]"
                )}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      {completedExercises[1] && <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e]" />}
                      Task 1: Inspect Email Lure
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-[#2563eb]/20 text-[#3b82f6] rounded border border-[#2563eb]/30">BASIC</span>
                  </div>
                  <p className="text-xs text-[#94a3b8] font-sans leading-relaxed">
                    Locate the phishing lure email artifact `urgent_invoice.eml` in the campaign node network.
                  </p>
                  <button
                    onClick={() => focusNodeById('urgent_invoice.eml', 1)}
                    className="w-full py-1.5 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Target className="w-3.5 h-3.5 text-[#3b82f6]" />
                    <span>Focus Email Node</span>
                  </button>
                </div>

                {/* Exercise 2 */}
                <div className={cn(
                  "bg-[#090d16] border rounded p-4 space-y-3 transition-colors",
                  completedExercises[2] ? "border-[#22c55e]/50 bg-[#22c55e]/5" : "border-[#232e42]"
                )}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      {completedExercises[2] && <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e]" />}
                      Task 2: Trace Phishing Domain
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-[#f97316]/20 text-[#f97316] rounded border border-[#f97316]/30">INTERMEDIATE</span>
                  </div>
                  <p className="text-xs text-[#94a3b8] font-sans leading-relaxed">
                    Identify the typo-squatted domain registered &lt; 72 hours ago targeting user credentials.
                  </p>
                  <button
                    onClick={() => focusNodeById('secure-paypal-update-auth.com', 2)}
                    className="w-full py-1.5 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Target className="w-3.5 h-3.5 text-[#f97316]" />
                    <span>Focus Phishing Domain</span>
                  </button>
                </div>

                {/* Exercise 3 */}
                <div className={cn(
                  "bg-[#090d16] border rounded p-4 space-y-3 transition-colors",
                  completedExercises[3] ? "border-[#22c55e]/50 bg-[#22c55e]/5" : "border-[#232e42]"
                )}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      {completedExercises[3] && <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e]" />}
                      Task 3: Locate Origin IP & C2
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-[#2563eb]/20 text-[#3b82f6] rounded border border-[#2563eb]/30">INTERMEDIATE</span>
                  </div>
                  <p className="text-xs text-[#94a3b8] font-sans leading-relaxed">
                    Trace the hosting IP `192.168.45.221` and its C2 beacon connections.
                  </p>
                  <button
                    onClick={() => focusNodeById('192.168.45.221', 3)}
                    className="w-full py-1.5 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Target className="w-3.5 h-3.5 text-[#3b82f6]" />
                    <span>Focus IP Node (192.168.45.221)</span>
                  </button>
                </div>

                {/* Exercise 4 */}
                <div className={cn(
                  "bg-[#090d16] border rounded p-4 space-y-3 transition-colors",
                  completedExercises[4] ? "border-[#22c55e]/50 bg-[#22c55e]/5" : "border-[#232e42]"
                )}>
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-white flex items-center gap-1.5">
                      {completedExercises[4] && <CheckCircle2 className="w-3.5 h-3.5 text-[#22c55e]" />}
                      Task 4: Threat Actor Pivot
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 bg-purple-500/20 text-purple-400 rounded border border-purple-500/30">ADVANCED</span>
                  </div>
                  <p className="text-xs text-[#94a3b8] font-sans leading-relaxed">
                    Pivot to UNC-2452 threat actor infrastructure and export IOC rules.
                  </p>
                  <button
                    onClick={() => focusNodeById('UNC-2452', 4)}
                    className="w-full py-1.5 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded flex items-center justify-center gap-1.5 transition-colors cursor-pointer"
                  >
                    <Target className="w-3.5 h-3.5 text-purple-400" />
                    <span>Focus Threat Actor UNC-2452</span>
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* STATE 3: Dynamic Active Campaign Summary */
            <div className="flex-1 flex flex-col h-full overflow-hidden">
              <div className="p-5 border-b border-[#232e42] flex items-start justify-between">
                <div>
                  <span className="text-[10px] font-bold text-[#64748b] uppercase tracking-wider block font-mono">
                    Investigation Panel — Workspace Campaign Status
                  </span>
                  <h2 className="text-xl font-bold text-white tracking-tight mt-0.5">
                    {data?.campaign_id ? `Campaign ${data.campaign_id}` : rawGraphData.nodes.length > 0 ? 'Active Correlation Cluster' : 'No Active Campaigns'}
                  </h2>
                  <p className="text-xs text-[#94a3b8] font-mono mt-1">
                    {rawGraphData.nodes.length > 0 ? `${rawGraphData.nodes.length} Entities & ${rawGraphData.links.length} Connected Pivots` : 'No entity nodes analyzed in workspace'}
                  </p>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-5 space-y-6">
                {/* Hover Helper Notice */}
                <div className="bg-[#090d16] border border-[#3b82f6]/30 rounded p-3 text-xs text-[#94a3b8] font-mono flex items-center gap-2">
                  <Target className="w-4 h-4 text-[#3b82f6] shrink-0" />
                  <span>Hover or touch any node to highlight connected relationship links and inspect telemetry.</span>
                </div>

                {/* Metric Cards */}
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-[#161c2b] border border-[#232e42] rounded p-4 space-y-1">
                    <span className="text-[10px] font-semibold text-[#94a3b8] uppercase tracking-wider block font-mono">
                      Graph Entities
                    </span>
                    <span className="text-3xl font-extrabold text-white font-mono">
                      {rawGraphData.nodes.length}
                    </span>
                  </div>

                  <div className="bg-[#161c2b] border border-[#232e42] rounded p-4 space-y-1">
                    <span className="text-[10px] font-semibold text-[#94a3b8] uppercase tracking-wider block font-mono">
                      Risk Level
                    </span>
                    <span className={cn(
                      "text-2xl font-extrabold font-mono block mt-1",
                      rawGraphData.nodes.length === 0 ? "text-[#94a3b8]" : "text-[#f97316]"
                    )}>
                      {rawGraphData.nodes.length === 0 ? "NONE" : "ACTIVE"}
                    </span>
                  </div>
                </div>

                {/* Detected Patterns */}
                <div className="space-y-3">
                  <span className="text-[10px] font-bold text-[#64748b] uppercase tracking-wider block font-mono">
                    DETECTED PATTERNS
                  </span>
                  {rawGraphData.nodes.length === 0 ? (
                    <div className="bg-[#090d16] border border-[#232e42] rounded p-3 text-xs text-[#94a3b8] font-mono">
                      No threat patterns detected in this workspace yet.
                    </div>
                  ) : (
                    <div className="space-y-2 text-xs text-white">
                      <div className="flex items-center gap-2.5 bg-[#090d16] border border-[#232e42] rounded p-2.5">
                        <Key className="w-4 h-4 text-[#3b82f6] shrink-0" />
                        <span className="font-semibold">Correlation Cluster Active</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Artifact Composition Table */}
                <div className="space-y-3">
                  <span className="text-[10px] font-bold text-[#64748b] uppercase tracking-wider block font-mono">
                    ARTIFACT COMPOSITION
                  </span>
                  <div className="bg-[#090d16] border border-[#232e42] rounded overflow-hidden">
                    <table className="w-full text-left text-xs font-mono">
                      <thead className="bg-[#121824] border-b border-[#232e42] text-[#64748b] font-semibold">
                        <tr>
                          <th className="py-2 px-3">Type</th>
                          <th className="py-2 px-3 text-right">Count</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#232e42] text-white">
                        <tr>
                          <td className="py-2.5 px-3 flex items-center gap-2 font-sans">
                            <Globe className="w-3.5 h-3.5 text-[#3b82f6]" />
                            <span>Domains</span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold">{artifactComposition.domainCount}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-3 flex items-center gap-2 font-sans">
                            <Server className="w-3.5 h-3.5 text-[#f97316]" />
                            <span>IP Addresses</span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold">{artifactComposition.ipCount}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-3 flex items-center gap-2 font-sans">
                            <FileText className="w-3.5 h-3.5 text-[#3b82f6]" />
                            <span>File Hashes / IOCs</span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold">{artifactComposition.hashCount}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-3 flex items-center gap-2 font-sans">
                            <Mail className="w-3.5 h-3.5 text-[#3b82f6]" />
                            <span>Emails</span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-bold">{artifactComposition.emailCount}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* Bottom Action Area */}
              <div className="p-4 border-t border-[#232e42] grid grid-cols-2 gap-3 bg-[#090d16]">
                <button
                  type="button"
                  onClick={handleExportGraph}
                  className="px-3 py-2 bg-[#121824] hover:bg-[#161c2b] border border-[#232e42] text-white text-xs font-semibold rounded transition-colors font-mono cursor-pointer"
                >
                  Export IOCs
                </button>
                <button
                  type="button"
                  onClick={() => console.log('Rule created from campaign artifacts.')}
                  className="px-3 py-2 bg-[#2563eb] hover:bg-[#1d4ed8] text-white text-xs font-semibold rounded transition-colors font-mono cursor-pointer"
                >
                  Create Rule
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
