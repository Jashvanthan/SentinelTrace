// SentinelTrace Frontend — Ultra-High Contrast 3D Animated Browser Tab Favicon Icon

import { useEffect } from 'react';

export function AnimatedFavicon() {
  useEffect(() => {
    // 64x64 Retina canvas for sharp, pixel-perfect browser tab icon rendering
    const canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Remove static icon link elements to prevent browser asset caching lock
    const existingIcons = document.querySelectorAll("link[rel*='icon']");
    existingIcons.forEach((el) => el.remove());

    // Create fresh dynamic favicon link node
    const link = document.createElement('link');
    link.id = 'dynamic-3d-favicon';
    link.rel = 'icon';
    link.type = 'image/png';
    document.head.appendChild(link);

    let angle = 0;

    const updateFavicon = () => {
      angle += 0.16;
      ctx.clearRect(0, 0, 64, 64);

      const cx = 32;
      const cy = 32;
      const radius = 17;

      // 1. High-Visibility Outer Cyan Aura Glow (ensures pop on dark & light browser themes)
      const aura = ctx.createRadialGradient(cx, cy, radius * 0.5, cx, cy, radius * 1.8);
      aura.addColorStop(0, 'rgba(0, 240, 255, 0.75)');
      aura.addColorStop(0.5, 'rgba(14, 165, 233, 0.35)');
      aura.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = aura;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.8, 0, 2 * Math.PI);
      ctx.fill();

      // 2. Back Orbit Ring 1 (behind planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 29, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.85)';
      ctx.lineWidth = 4.5;
      ctx.stroke();
      ctx.restore();

      // 3. Back Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 31, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.7)';
      ctx.lineWidth = 3.5;
      ctx.stroke();
      ctx.restore();

      // 4. Central 3D Vibrant Planet Body
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      
      const sphereGrad = ctx.createRadialGradient(
        cx - 5,
        cy - 6,
        1,
        cx,
        cy,
        radius
      );
      sphereGrad.addColorStop(0, '#ffffff');
      sphereGrad.addColorStop(0.25, '#38bdf8');
      sphereGrad.addColorStop(0.65, '#0284c7');
      sphereGrad.addColorStop(1, '#0369a1');

      ctx.fillStyle = sphereGrad;
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 12;
      ctx.fill();
      ctx.restore();

      // 5. White & Bright Pink 3D Surface Texture Motion
      for (let i = 0; i < 9; i++) {
        const phi = (i / 9) * Math.PI * 2;
        const xOff = Math.sin(angle + phi) * (radius * 0.7);
        const yOff = Math.cos((angle + phi) * 0.7) * (radius * 0.6);
        ctx.fillStyle = i % 2 === 0 ? '#f472b6' : '#ffffff';
        ctx.beginPath();
        ctx.arc(cx + xOff, cy + yOff, 2.2, 0, 2 * Math.PI);
        ctx.fill();
      }

      // 6. Front Orbit Ring 1 + Revolving Glowing Moon
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 29, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 4.5;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 8;
      ctx.stroke();

      const moonX = Math.cos(angle * 1.5) * 29;
      const moonY = Math.sin(angle * 1.5) * 29;
      ctx.fillStyle = '#ffffff';
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 10;
      ctx.beginPath();
      ctx.arc(moonX, moonY, 4.5, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();

      // 7. Front Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 31, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.95)';
      ctx.lineWidth = 3.5;
      ctx.stroke();
      ctx.restore();

      // Refresh link element href data stream
      link.href = canvas.toDataURL('image/png');
    };

    // Update at 110ms interval (~9 FPS) — optimal rate for browser tab favicons
    const intervalId = setInterval(updateFavicon, 110);

    return () => {
      clearInterval(intervalId);
    };
  }, []);

  return null;
}
