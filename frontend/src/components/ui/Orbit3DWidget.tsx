// SentinelTrace Frontend — 3D Movable Orbiting Planet Widget & Interactive Tap Icon

import React, { useEffect, useRef, useState } from 'react';
import { Sparkles, Maximize2, Minimize2, Move } from 'lucide-react';
import { cn } from '@/utils';

export function Orbit3DWidget() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [position, setPosition] = useState({ x: window.innerWidth - 110, y: window.innerHeight - 130 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [isMinimized, setIsMinimized] = useState(false);
  const [tapEffect, setTapEffect] = useState(false);

  // Rotation speed & interactive physics
  const speedRef = useRef(0.015);
  const angleRef = useRef(0);
  const ringAngleRef = useRef(0);
  const clickBoostRef = useRef(0);

  // Keep widget inside viewport on resize
  useEffect(() => {
    const handleResize = () => {
      setPosition((prev) => ({
        x: Math.min(prev.x, window.innerWidth - 100),
        y: Math.min(prev.y, window.innerHeight - 100),
      }));
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // ── 3D Canvas Renderer ──────────────────────────────────────────────────────
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
      const baseRadius = 26;

      ctx.clearRect(0, 0, width, height);

      // Speed boosting on tap
      clickBoostRef.current *= 0.94;
      angleRef.current += speedRef.current + clickBoostRef.current * 0.05;
      ringAngleRef.current += 0.01;

      const angle = angleRef.current;
      const currentRadius = baseRadius + Math.sin(angle * 2) * 0.8 + (clickBoostRef.current > 0.01 ? Math.sin(angle * 10) * 2 : 0);

      // 1. Back section of Orbit Ring 1 (behind planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 48, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.45)';
      ctx.lineWidth = 3.5;
      ctx.stroke();
      ctx.restore();

      // 2. Back section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 52, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.25)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.restore();

      // 3. Planet Shadow & Ambient Glow
      const ambientGlow = ctx.createRadialGradient(cx, cy, currentRadius * 0.5, cx, cy, currentRadius * 2.2);
      ambientGlow.addColorStop(0, 'rgba(56, 189, 248, 0.3)');
      ambientGlow.addColorStop(0.6, 'rgba(37, 99, 235, 0.15)');
      ambientGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = ambientGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius * 2.2, 0, 2 * Math.PI);
      ctx.fill();

      // 4. Main 3D Sphere Body with Gradient & Speckles
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius, 0, 2 * Math.PI);
      
      const sphereGrad = ctx.createRadialGradient(
        cx - currentRadius * 0.3,
        cy - currentRadius * 0.4,
        currentRadius * 0.1,
        cx,
        cy,
        currentRadius
      );
      sphereGrad.addColorStop(0, '#7dd3fc');
      sphereGrad.addColorStop(0.4, '#0ea5e9');
      sphereGrad.addColorStop(0.85, '#0284c7');
      sphereGrad.addColorStop(1, '#0369a1');

      ctx.fillStyle = sphereGrad;
      ctx.shadowColor = 'rgba(14, 165, 233, 0.6)';
      ctx.shadowBlur = 12;
      ctx.fill();
      ctx.restore();

      // 5. Pink/White Surface Speckles (3D rotation simulation)
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius - 0.5, 0, 2 * Math.PI);
      ctx.clip();

      const speckleCount = 14;
      for (let i = 0; i < speckleCount; i++) {
        const phi = (i / speckleCount) * Math.PI * 2;
        const speed = angle + i;
        const xOffset = Math.sin(speed + phi) * (currentRadius * 0.75);
        const yOffset = Math.cos((speed + phi) * 0.7) * (currentRadius * 0.65);
        const size = (Math.sin(speed * 2) + 1.5) * 1.2;

        ctx.fillStyle = i % 2 === 0 ? 'rgba(255, 192, 203, 0.85)' : 'rgba(255, 255, 255, 0.9)';
        ctx.beginPath();
        ctx.arc(cx + xOffset, cy + yOffset, Math.max(0.8, size), 0, 2 * Math.PI);
        ctx.fill();
      }
      ctx.restore();

      // 6. Front section of Orbit Ring 1 (overlaps planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 48, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 3.5;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 8;
      ctx.stroke();

      // Satellite moon on Ring 1
      const moonX = Math.cos(angle * 1.5) * 48;
      const moonY = Math.sin(angle * 1.5) * 48;
      ctx.fillStyle = '#bae6fd';
      ctx.beginPath();
      ctx.arc(moonX, moonY, 4.5, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();

      // 7. Front section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 52, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.8)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.restore();

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, []);

  // ── Drag & Move Handlers ────────────────────────────────────────────────────
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragOffset({
      x: e.clientX - position.x,
      y: e.clientY - position.y,
    });
  };

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isDragging) return;
      const newX = Math.max(10, Math.min(window.innerWidth - 110, e.clientX - dragOffset.x));
      const newY = Math.max(10, Math.min(window.innerHeight - 110, e.clientY - dragOffset.y));
      setPosition({ x: newX, y: newY });
    };

    const handleMouseUp = () => {
      setIsDragging(false);
    };

    if (isDragging) {
      window.addEventListener('mousemove', handleMouseMove);
      window.addEventListener('mouseup', handleMouseUp);
    }
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isDragging, dragOffset]);

  // ── Tap / Click Boost Handler ───────────────────────────────────────────────
  const handleTap = () => {
    clickBoostRef.current = 1.2;
    setTapEffect(true);
    setTimeout(() => setTapEffect(false), 600);
  };

  return (
    <div
      style={{ left: `${position.x}px`, top: `${position.y}px` }}
      className={cn(
        'fixed z-50 select-none group transition-shadow duration-300',
        isDragging ? 'cursor-grabbing' : 'cursor-grab'
      )}
    >
      <div className="relative flex flex-col items-center">
        {/* Drag Handle Bar */}
        <div
          onMouseDown={handleMouseDown}
          className="absolute -top-6 bg-[#0f172a]/80 backdrop-blur-md border border-[#38bdf8]/40 rounded-full px-2 py-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1 text-[10px] text-[#7dd3fc] cursor-move shadow-lg"
        >
          <Move className="w-2.5 h-2.5 text-[#38bdf8]" />
          <span>Move</span>
        </div>

        {/* 3D Canvas Planet Container */}
        <div
          onClick={handleTap}
          className={cn(
            'relative rounded-full p-2 bg-[#090d16]/70 backdrop-blur-md border border-[#38bdf8]/30 shadow-2xl transition-all duration-300 hover:scale-110 active:scale-95',
            tapEffect && 'ring-4 ring-[#38bdf8]/60 shadow-[0_0_30px_rgba(56,189,248,0.8)]'
          )}
        >
          {!isMinimized && (
            <canvas
              ref={canvasRef}
              width={100}
              height={100}
              className="w-20 h-20 drop-shadow-[0_0_15px_rgba(14,165,233,0.5)] cursor-pointer"
            />
          )}

          {isMinimized && (
            <div className="w-10 h-10 flex items-center justify-center text-[#38bdf8] font-bold text-xs font-mono">
              3D
            </div>
          )}

          {/* Sparkle Burst Effect on Tap */}
          {tapEffect && (
            <div className="absolute inset-0 flex items-center justify-center pointer-events-none animate-ping">
              <Sparkles className="w-8 h-8 text-[#7dd3fc]" />
            </div>
          )}
        </div>

        {/* Minimize / Expand Toggle Button */}
        <button
          onClick={(e) => {
            e.stopPropagation();
            setIsMinimized(!isMinimized);
          }}
          className="mt-1 bg-[#0d121d]/90 hover:bg-[#1e293b] border border-[#334155] rounded-full p-1 text-[#94a3b8] hover:text-white transition-colors cursor-pointer shadow-md"
          title={isMinimized ? 'Expand 3D Planet' : 'Minimize Widget'}
        >
          {isMinimized ? <Maximize2 className="w-3 h-3" /> : <Minimize2 className="w-3 h-3" />}
        </button>
      </div>
    </div>
  );
}
