// SentinelTrace Frontend — 3D Movable & Clickable Orbiting Planet Logo (Transparent Background)

import React, { useEffect, useRef, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { cn } from '@/utils';

export function Orbit3DWidget() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [position, setPosition] = useState({ x: window.innerWidth - 130, y: window.innerHeight - 140 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });
  const [tapEffect, setTapEffect] = useState(false);

  const startPosRef = useRef({ x: 0, y: 0 });
  const hasMovedRef = useRef(false);

  // Rotation speed & interactive physics
  const speedRef = useRef(0.02);
  const angleRef = useRef(0);
  const clickBoostRef = useRef(0);

  // Keep widget inside viewport on resize
  useEffect(() => {
    const handleResize = () => {
      setPosition((prev) => ({
        x: Math.min(prev.x, window.innerWidth - 120),
        y: Math.min(prev.y, window.innerHeight - 120),
      }));
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  // ── 3D Canvas Renderer (100% Transparent Background) ─────────────────────────
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

      // Speed boosting on tap
      clickBoostRef.current *= 0.94;
      angleRef.current += speedRef.current + clickBoostRef.current * 0.06;
      const angle = angleRef.current;
      const currentRadius = baseRadius + (clickBoostRef.current > 0.01 ? Math.sin(angle * 12) * 2.5 : 0);

      // 1. Back section of Orbit Ring 1 (behind planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 52, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.65)';
      ctx.lineWidth = 4;
      ctx.stroke();
      ctx.restore();

      // 2. Back section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 56, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(125, 211, 252, 0.45)';
      ctx.lineWidth = 3;
      ctx.stroke();
      ctx.restore();

      // 3. Ambient Glow Aura
      const ambientGlow = ctx.createRadialGradient(cx, cy, currentRadius * 0.4, cx, cy, currentRadius * 2.3);
      ambientGlow.addColorStop(0, 'rgba(56, 189, 248, 0.45)');
      ambientGlow.addColorStop(0.5, 'rgba(37, 99, 235, 0.2)');
      ambientGlow.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = ambientGlow;
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius * 2.3, 0, 2 * Math.PI);
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
      sphereGrad.addColorStop(0, '#bae6fd');
      sphereGrad.addColorStop(0.35, '#38bdf8');
      sphereGrad.addColorStop(0.75, '#0284c7');
      sphereGrad.addColorStop(1, '#0369a1');

      ctx.fillStyle = sphereGrad;
      ctx.shadowColor = 'rgba(56, 189, 248, 0.8)';
      ctx.shadowBlur = 18;
      ctx.fill();
      ctx.restore();

      // 5. Bright Pink & White Surface Speckles (3D texture animation)
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, currentRadius - 0.5, 0, 2 * Math.PI);
      ctx.clip();

      const speckleCount = 16;
      for (let i = 0; i < speckleCount; i++) {
        const phi = (i / speckleCount) * Math.PI * 2;
        const speed = angle + i;
        const xOffset = Math.sin(speed + phi) * (currentRadius * 0.75);
        const yOffset = Math.cos((speed + phi) * 0.7) * (currentRadius * 0.65);
        const size = (Math.sin(speed * 2) + 1.5) * 1.3;

        ctx.fillStyle = i % 2 === 0 ? '#f472b6' : '#ffffff';
        ctx.beginPath();
        ctx.arc(cx + xOffset, cy + yOffset, Math.max(1, size), 0, 2 * Math.PI);
        ctx.fill();
      }
      ctx.restore();

      // 6. Front section of Orbit Ring 1 (overlaps planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 52, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 4;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 10;
      ctx.stroke();

      // Revolving Satellite Moon
      const moonX = Math.cos(angle * 1.5) * 52;
      const moonY = Math.sin(angle * 1.5) * 52;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(moonX, moonY, 5, 0, 2 * Math.PI);
      ctx.shadowColor = '#38bdf8';
      ctx.shadowBlur = 8;
      ctx.fill();
      ctx.restore();

      // 7. Front section of Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 56, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.lineWidth = 3;
      ctx.stroke();
      ctx.restore();

      animationId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, []);

  // ── Mouse & Touch Movable / Drag Handlers ────────────────────────────────────
  const handlePointerDown = (e: React.PointerEvent) => {
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
    if (!isDragging) return;
    const distMoved = Math.hypot(e.clientX - startPosRef.current.x, e.clientY - startPosRef.current.y);
    if (distMoved > 4) {
      hasMovedRef.current = true;
    }
    const newX = Math.max(10, Math.min(window.innerWidth - 120, e.clientX - dragOffset.x));
    const newY = Math.max(10, Math.min(window.innerHeight - 120, e.clientY - dragOffset.y));
    setPosition({ x: newX, y: newY });
  };

  const handlePointerUp = (e: React.PointerEvent) => {
    if (isDragging) {
      setIsDragging(false);
      try {
        (e.target as HTMLElement).releasePointerCapture(e.pointerId);
      } catch {
        // Pointer capture release non-fatal
      }
      // If user tapped without dragging, trigger 3D spin burst effect
      if (!hasMovedRef.current) {
        clickBoostRef.current = 1.4;
        setTapEffect(true);
        setTimeout(() => setTapEffect(false), 700);
      }
    }
  };

  return (
    <div
      style={{ left: `${position.x}px`, top: `${position.y}px` }}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerUp}
      className={cn(
        'fixed z-50 select-none touch-none bg-transparent border-0 outline-none',
        isDragging ? 'cursor-grabbing' : 'cursor-grab'
      )}
      title="Tap or Drag to move 3D Sentinel Orbit"
    >
      <div className="relative flex items-center justify-center p-0 bg-transparent">
        {/* Transparent 3D Canvas Button — No dark box / no black background */}
        <canvas
          ref={canvasRef}
          width={120}
          height={120}
          className={cn(
            'w-28 h-28 transition-transform duration-200 bg-transparent',
            'hover:scale-110 active:scale-95 drop-shadow-[0_0_20px_rgba(56,189,248,0.7)]',
            tapEffect && 'scale-125'
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
  );
}
