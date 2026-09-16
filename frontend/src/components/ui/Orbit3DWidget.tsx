// SentinelTrace Frontend — 3D Movable & Clickable Orbiting Planet Logo with Hyper-Drive Reload Animation

import React, { useEffect, useRef, useState, useCallback } from 'react';
import { Sparkles, RefreshCw, ShieldCheck, Zap } from 'lucide-react';
import { cn } from '@/utils';

export function Orbit3DWidget() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const overlayCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const [position, setPosition] = useState(() => {
    return {
      x: typeof window !== 'undefined' ? Math.max(20, window.innerWidth - 140) : 800,
      y: typeof window !== 'undefined' ? Math.max(20, window.innerHeight - 150) : 600,
    };
  });

  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [tapEffect, setTapEffect] = useState(false);
  const [showTooltip, setShowTooltip] = useState(false);
  const [isReloading, setIsReloading] = useState(false);
  const [reloadProgress, setReloadProgress] = useState(0);
  const [reloadStatusText, setReloadStatusText] = useState('INITIATING QUANTUM SYNC...');
  const [justReloaded, setJustReloaded] = useState(false);

  const startPosRef = useRef({ x: 0, y: 0 });
  const hasMovedRef = useRef(false);
  const lastClickTimeRef = useRef(0);
  const singleClickTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tooltipTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Rotation speed & interactive physics
  const speedRef = useRef(0.02);
  const angleRef = useRef(0);
  const clickBoostRef = useRef(0);
  const isReloadingRef = useRef(false);
  const reloadWarpFactorRef = useRef(1);

  // Check if page was just reloaded
  useEffect(() => {
    try {
      const wasReloaded = sessionStorage.getItem('sentinel_reloaded');
      if (wasReloaded === 'true') {
        sessionStorage.removeItem('sentinel_reloaded');
        setJustReloaded(true);
        clickBoostRef.current = 3.0; // Initial spin burst on entry
        const timer = setTimeout(() => {
          setJustReloaded(false);
        }, 3200);
        return () => clearTimeout(timer);
      }
    } catch {
      // Storage access check fallback
    }
  }, []);

  // Keep widget inside viewport on resize
  useEffect(() => {
    const handleResize = () => {
      setPosition((prev) => ({
        x: Math.min(Math.max(10, prev.x), window.innerWidth - 120),
        y: Math.min(Math.max(10, prev.y), window.innerHeight - 120),
      }));
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // Sync ref with state
  useEffect(() => {
    isReloadingRef.current = isReloading;
  }, [isReloading]);

  // ── Double Click Reload Handler ─────────────────────────────────────────────
  const triggerReloadAnimation = useCallback(() => {
    if (isReloadingRef.current) return;
    setIsReloading(true);
    isReloadingRef.current = true;
    setShowTooltip(false);
    if (singleClickTimerRef.current) {
      clearTimeout(singleClickTimerRef.current);
      singleClickTimerRef.current = null;
    }

    // Set flag in sessionStorage to recognize post-reload state
    try {
      sessionStorage.setItem('sentinel_reloaded', 'true');
    } catch {
      // ignore
    }

    // Sequence progress stages
    setReloadProgress(15);
    setReloadStatusText('INITIATING QUANTUM REFRESH...');

    const t1 = setTimeout(() => {
      setReloadProgress(50);
      setReloadStatusText('FLUSHING CACHES & WEBSOCKET SYNC...');
    }, 280);

    const t2 = setTimeout(() => {
      setReloadProgress(88);
      setReloadStatusText('RELOADING SENTINELTRACE SOC ENGINES...');
    }, 600);

    const t3 = setTimeout(() => {
      setReloadProgress(100);
      setReloadStatusText('SYSTEM SYNCED — REBOOTING PAGE...');
    }, 900);

    const t4 = setTimeout(() => {
      window.location.reload();
    }, 1100);

    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      clearTimeout(t4);
    };
  }, []);

  // ── Single Click Handler ───────────────────────────────────────────────────
  const handleSingleClick = useCallback(() => {
    clickBoostRef.current = 1.8;
    setTapEffect(true);
    setShowTooltip(true);

    if (tooltipTimeoutRef.current) clearTimeout(tooltipTimeoutRef.current);
    tooltipTimeoutRef.current = setTimeout(() => {
      setShowTooltip(false);
    }, 2800);

    setTimeout(() => setTapEffect(false), 600);
  }, []);

  // ── 3D Canvas Renderer (Movable Widget) ──────────────────────────────────
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationId: number;

    const render = () => {
      const width = canvas.width;
      const height = canvas.height;
      const cx = width / 2;
      const cy = height / 2;
      const baseRadius = 28;

      ctx.clearRect(0, 0, width, height);

      // Speed boosting & Warp acceleration during reloading
      const reloading = isReloadingRef.current;
      if (reloading) {
        reloadWarpFactorRef.current = Math.min(reloadWarpFactorRef.current + 0.15, 8);
      } else {
        reloadWarpFactorRef.current = Math.max(reloadWarpFactorRef.current - 0.05, 1);
      }

      clickBoostRef.current *= 0.93;
      const currentSpeed = (speedRef.current + clickBoostRef.current * 0.06) * reloadWarpFactorRef.current;
      angleRef.current += currentSpeed;
      const angle = angleRef.current;

      const currentRadius = baseRadius + (clickBoostRef.current > 0.01 || reloading ? Math.sin(angle * 12) * 3 : 0);

      // 0. Shockwave Ring on Hyper Warp
      if (reloading || reloadWarpFactorRef.current > 1.5) {
        ctx.save();
        ctx.beginPath();
        const shockRadius = (Math.sin(angle * 4) + 1) * 35 + 20;
        ctx.arc(cx, cy, shockRadius, 0, Math.PI * 2);
        ctx.strokeStyle = `rgba(56, 189, 248, ${0.8 - shockRadius / 80})`;
        ctx.lineWidth = 2;
        ctx.stroke();
        ctx.restore();
      }

      // 1. Back section of Orbit Ring 1 (behind planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6 + (reloading ? angle * 0.5 : 0));
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 52, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = reloading ? '#38bdf8' : 'rgba(255, 255, 255, 0.65)';
      ctx.lineWidth = reloading ? 6 : 4;
      ctx.stroke();
      ctx.restore();

      // 2. Back section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4 - (reloading ? angle * 0.7 : 0));
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 56, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = reloading ? '#0284c7' : 'rgba(125, 211, 252, 0.45)';
      ctx.lineWidth = reloading ? 5 : 3;
      ctx.stroke();
      ctx.restore();

      // 3. Ambient Glow Aura
      const ambientGlow = ctx.createRadialGradient(
        cx,
        cy,
        currentRadius * 0.4,
        cx,
        cy,
        currentRadius * (reloading ? 3.2 : 2.3)
      );
      ambientGlow.addColorStop(0, reloading ? 'rgba(56, 189, 248, 0.85)' : 'rgba(56, 189, 248, 0.45)');
      ambientGlow.addColorStop(0.5, reloading ? 'rgba(14, 165, 233, 0.5)' : 'rgba(37, 99, 235, 0.2)');
      ambientGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = ambientGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius * (reloading ? 3.2 : 2.3), 0, 2 * Math.PI);
      ctx.fill();

      // 4. Main 3D Sphere Body
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius, 0, 2 * Math.PI);

      const sphereGrad = ctx.createRadialGradient(
        cx - currentRadius * 0.35,
        cy - currentRadius * 0.4,
        currentRadius * 0.1,
        cx,
        cy,
        currentRadius
      );
      sphereGrad.addColorStop(0, reloading ? '#ffffff' : '#bae6fd');
      sphereGrad.addColorStop(0.35, '#38bdf8');
      sphereGrad.addColorStop(0.75, '#0284c7');
      sphereGrad.addColorStop(1, '#0369a1');

      ctx.fillStyle = sphereGrad;
      ctx.shadowColor = reloading ? '#00f0ff' : 'rgba(56, 189, 248, 0.8)';
      ctx.shadowBlur = reloading ? 30 : 18;
      ctx.fill();
      ctx.restore();

      // 5. Surface Speckles / Quantum Particles
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius - 0.5, 0, 2 * Math.PI);
      ctx.clip();

      const speckleCount = reloading ? 32 : 16;
      for (let i = 0; i < speckleCount; i++) {
        const phi = (i / speckleCount) * Math.PI * 2;
        const speed = angle * (reloading ? 2 : 1) + i;
        const xOffset = Math.sin(speed + phi) * (currentRadius * 0.75);
        const yOffset = Math.cos((speed + phi) * 0.7) * (currentRadius * 0.65);
        const size = (Math.sin(speed * 2) + 1.5) * (reloading ? 1.8 : 1.3);

        ctx.fillStyle = i % 3 === 0 ? '#f472b6' : i % 3 === 1 ? '#38bdf8' : '#ffffff';
        ctx.beginPath();
        ctx.arc(cx + xOffset, cy + yOffset, Math.max(1, size), 0, 2 * Math.PI);
        ctx.fill();
      }
      ctx.restore();

      // 6. Front section of Orbit Ring 1 (overlaps planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6 + (reloading ? angle * 0.5 : 0));
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 52, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = reloading ? 6 : 4;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = reloading ? 18 : 10;
      ctx.stroke();

      // Revolving Satellite Moon
      const moonX = Math.cos(angle * 1.5) * 52;
      const moonY = Math.sin(angle * 1.5) * 52;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(moonX, moonY, reloading ? 7 : 5, 0, 2 * Math.PI);
      ctx.shadowColor = '#38bdf8';
      ctx.shadowBlur = reloading ? 14 : 8;
      ctx.fill();
      ctx.restore();

      // 7. Front section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4 - (reloading ? angle * 0.7 : 0));
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 56, 0, Math.PI);
      ctx.strokeStyle = reloading ? '#bae6fd' : 'rgba(255, 255, 255, 0.9)';
      ctx.lineWidth = reloading ? 5 : 3;
      ctx.stroke();
      ctx.restore();

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, []);

  // ── Overlay Canvas Renderer during Reload ──────────────────────────────
  useEffect(() => {
    if (!isReloading) return;
    const overlayCanvas = overlayCanvasRef.current;
    if (!overlayCanvas) return;
    const ctx = overlayCanvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let time = 0;

    const resizeOverlay = () => {
      overlayCanvas.width = window.innerWidth;
      overlayCanvas.height = window.innerHeight;
    };
    resizeOverlay();
    window.addEventListener('resize', resizeOverlay);

    // Particle system for overlay
    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      alpha: number;
      color: string;
    }> = [];

    const width = window.innerWidth;
    const height = window.innerHeight;
    for (let i = 0; i < 75; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 4,
        vy: (Math.random() - 0.5) * 4,
        size: Math.random() * 3 + 1,
        alpha: Math.random() * 0.7 + 0.3,
        color: i % 2 === 0 ? '#38bdf8' : '#f472b6',
      });
    }

    const drawOverlay = () => {
      time += 0.04;
      const w = overlayCanvas.width;
      const h = overlayCanvas.height;
      const cx = w / 2;
      const cy = h / 2;

      ctx.clearRect(0, 0, w, h);

      // Holographic grid lines
      ctx.save();
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.08)';
      ctx.lineWidth = 1;
      const gridSize = 40;
      for (let x = 0; x < w; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, h);
        ctx.stroke();
      }
      for (let y = 0; y < h; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(w, y);
        ctx.stroke();
      }
      ctx.restore();

      // Scanning HUD Beam
      ctx.save();
      const scanY = (Math.sin(time * 2) * 0.5 + 0.5) * h;
      const grad = ctx.createLinearGradient(0, scanY - 30, 0, scanY + 30);
      grad.addColorStop(0, 'rgba(56, 189, 248, 0)');
      grad.addColorStop(0.5, 'rgba(56, 189, 248, 0.25)');
      grad.addColorStop(1, 'rgba(56, 189, 248, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, scanY - 30, w, 60);

      ctx.strokeStyle = 'rgba(56, 189, 248, 0.6)';
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      ctx.moveTo(0, scanY);
      ctx.lineTo(w, scanY);
      ctx.stroke();
      ctx.restore();

      // Central Rotating Cyber HUD Ring
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(time * 0.8);
      ctx.beginPath();
      ctx.arc(0, 0, 110, 0, Math.PI * 1.5);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.4)';
      ctx.lineWidth = 2;
      ctx.setLineDash([8, 12]);
      ctx.stroke();

      ctx.rotate(-time * 1.6);
      ctx.beginPath();
      ctx.arc(0, 0, 130, 0, Math.PI * 1.8);
      ctx.strokeStyle = 'rgba(244, 114, 182, 0.35)';
      ctx.lineWidth = 1.5;
      ctx.setLineDash([14, 10]);
      ctx.stroke();
      ctx.restore();

      // Flying particles
      particles.forEach((p) => {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0) p.x = w;
        if (p.x > w) p.x = 0;
        if (p.y < 0) p.y = h;
        if (p.y > h) p.y = 0;

        ctx.save();
        ctx.fillStyle = p.color;
        ctx.globalAlpha = p.alpha;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 8;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fill();
        ctx.restore();
      });

      animId = requestAnimationFrame(drawOverlay);
    };

    drawOverlay();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', resizeOverlay);
    };
  }, [isReloading]);

  // ── Mouse & Touch Movable / Drag / Double Click Handlers ─────────────────
  const handlePointerDown = (e: React.PointerEvent) => {
    if (isReloading) return;
    setIsDragging(true);
    hasMovedRef.current = false;
    startPosRef.current = { x: e.clientX, y: e.clientY };
    setDragOffset({
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    });
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
  };

  const handlePointerMove = (e: React.PointerEvent) => {
    if (!isDragging || isReloading) return;
    const distMoved = Math.hypot(e.clientX - startPosRef.current.x, e.clientY - startPosRef.current.y);
    if (distMoved > 5) {
      hasMovedRef.current = true;
    }
    const newX = Math.max(10, Math.min(window.innerWidth - 120, e.clientX - dragOffset.x));
    const newY = Math.max(10, Math.min(window.innerHeight - 120, e.clientY - dragOffset.y));
    setPosition({ x: newX, y: newY });
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    if (isReloading) return;
    if (isDragging) {
      setIsDragging(false);
      try {
        (e.target as HTMLElement).releasePointerCapture(e.pointerId);
      } catch {
        // non-fatal
      }

      // If user clicked/tapped without dragging:
      if (!hasMovedRef.current) {
        const now = Date.now();
        const timeSinceLastClick = now - lastClickTimeRef.current;

        // Double-click threshold: 350ms
        if (timeSinceLastClick > 0 && timeSinceLastClick < 350) {
          lastClickTimeRef.current = 0;
          triggerReloadAnimation();
        } else {
          lastClickTimeRef.current = now;
          // Delay single-click reaction slightly to check if second click follows
          if (singleClickTimerRef.current) clearTimeout(singleClickTimerRef.current);
          singleClickTimerRef.current = setTimeout(() => {
            handleSingleClick();
          }, 240);
        }
      }
    }
  };

  // Explicit React Double Click Handler (for standard mouse events)
  const handleNativeDoubleClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    triggerReloadAnimation();
  };

  return (
    <>
      {/* ── FULL-SCREEN QUANTUM SOC RELOAD OVERLAY ───────────────────────── */}
      {isReloading && (
        <div className="fixed inset-0 z-[100] flex flex-col items-center justify-center bg-[#090d16]/92 backdrop-blur-md select-none transition-opacity duration-300">
          <canvas ref={overlayCanvasRef} className="absolute inset-0 pointer-events-none" />

          {/* Central Animated Reload Card */}
          <div className="relative z-10 flex flex-col items-center px-8 py-7 rounded-2xl bg-[#0d121d]/90 border border-[#38bdf8]/40 shadow-[0_0_50px_rgba(56,189,248,0.25)] max-w-md w-full text-center">
            {/* Pulsing Outer Atom Ring */}
            <div className="relative flex items-center justify-center w-28 h-28 mb-5">
              <div className="absolute inset-0 rounded-full border-2 border-dashed border-[#38bdf8] animate-spin [animation-duration:4s]" />
              <div className="absolute inset-2 rounded-full border border-pink-500/40 animate-ping [animation-duration:2s]" />

              {/* Central Glowing Icon */}
              <div className="w-20 h-20 rounded-full bg-gradient-to-tr from-[#0284c7] via-[#38bdf8] to-[#bae6fd] flex items-center justify-center shadow-[0_0_30px_#38bdf8] animate-pulse">
                <RefreshCw className="w-10 h-10 text-white animate-spin [animation-duration:1s]" />
              </div>
            </div>

            {/* Title & Status */}
            <h2 className="text-xl font-bold text-white tracking-wide font-mono flex items-center justify-center gap-2">
              <Zap className="w-5 h-5 text-[#38bdf8] animate-bounce" />
              <span>SENTINELTRACE SYNC</span>
            </h2>

            <p className="text-xs text-[#38bdf8] font-mono tracking-wider uppercase mt-2 h-5">
              {reloadStatusText}
            </p>

            {/* Futuristic Progress Bar */}
            <div className="w-full bg-[#121824] border border-[#232e42] h-3 rounded-full mt-5 overflow-hidden p-0.5 relative">
              <div
                className="h-full bg-gradient-to-r from-[#2563eb] via-[#38bdf8] to-pink-500 rounded-full transition-all duration-300 shadow-[0_0_12px_#38bdf8]"
                style={{ width: `${reloadProgress}%` }}
              />
            </div>

            <div className="flex justify-between w-full text-[10px] font-mono text-[#64748b] mt-2">
              <span>SOC ENGINES</span>
              <span>{reloadProgress}%</span>
            </div>
          </div>
        </div>
      )}

      {/* ── POST-RELOAD SUCCESS NOTIFICATION TOAST ───────────────────────── */}
      {justReloaded && !isReloading && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[90] flex items-center gap-2.5 px-4 py-2.5 rounded-xl bg-[#0d121d]/95 border border-[#22c55e]/50 text-white shadow-[0_0_25px_rgba(34,197,94,0.3)] animate-in fade-in slide-in-from-bottom-4 duration-300">
          <ShieldCheck className="w-5 h-5 text-[#22c55e] flex-shrink-0 animate-pulse" />
          <span className="text-xs font-mono font-medium text-slate-200">
            SOC Dashboard Reloaded & Synchronized
          </span>
          <span className="text-[10px] font-mono bg-[#22c55e]/20 text-[#4ade80] px-2 py-0.5 rounded border border-[#22c55e]/40">
            LIVE
          </span>
        </div>
      )}

      {/* ── 3D MOVABLE WIDGET BUTTON ─────────────────────────────────────── */}
      <div
        style={{ left: `${position.x}px`, top: `${position.y}px` }}
        onPointerDown={handlePointerDown}
        onPointerMove={handlePointerMove}
        onPointerUp={handlePointerUp}
        onPointerCancel={handlePointerUp}
        onDoubleClick={handleNativeDoubleClick}
        className={cn(
          'fixed z-50 select-none touch-none bg-transparent border-0 outline-none transition-transform duration-75',
          isDragging ? 'cursor-grabbing scale-105' : 'cursor-grab',
          isReloading && 'pointer-events-none opacity-0'
        )}
        title="Double-click to Reload Page | Drag to Move"
      >
        <div className="relative flex items-center justify-center p-0 bg-transparent group">
          {/* Tooltip Badge on Single Click or Hover */}
          {(showTooltip || justReloaded) && (
            <div className="absolute -top-10 left-1/2 -translate-x-1/2 whitespace-nowrap bg-[#0d121d]/95 border border-[#38bdf8]/50 text-[#bae6fd] text-[11px] font-mono px-3 py-1 rounded-full shadow-[0_0_15px_rgba(56,189,248,0.4)] pointer-events-none animate-in fade-in zoom-in-95 duration-150 flex items-center gap-1.5 z-10">
              <RefreshCw className="w-3 h-3 text-[#38bdf8] animate-spin" />
              <span>Double-click to Reload</span>
            </div>
          )}

          {/* Transparent 3D Canvas Button */}
          <canvas
            ref={canvasRef}
            width={120}
            height={120}
            className={cn(
              'w-28 h-28 transition-all duration-200 bg-transparent',
              'hover:scale-110 active:scale-95 drop-shadow-[0_0_20px_rgba(56,189,248,0.7)]',
              tapEffect && 'scale-125',
              justReloaded && 'drop-shadow-[0_0_30px_rgba(34,197,94,0.9)]'
            )}
          />

          {/* Sparkle Burst Effect on Tap */}
          {tapEffect && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none animate-ping">
              <Sparkles className="w-12 h-12 text-[#bae6fd]" />
            </div>
          )}
        </div>
      </div>
    </>
  );
}

