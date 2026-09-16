// SentinelTrace Frontend — Maximized 128x128 3D Animated Browser Tab Favicon Icon

import { useEffect } from 'react';

export function AnimatedFavicon() {
  useEffect(() => {
    // 128x128 High-density Canvas to maximize icon size & clarity in browser tab
    const canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Remove static icon link elements to prevent asset caching lock
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
      ctx.clearRect(0, 0, 128, 128);

      const cx = 64;
      const cy = 64;
      const radius = 35; // Maximized planet radius

      // 1. Maximized High-Visibility Outer Cyan Aura Glow
      const aura = ctx.createRadialGradient(cx, cy, radius * 0.4, cx, cy, radius * 1.7);
      aura.addColorStop(0, 'rgba(0, 240, 255, 0.85)');
      aura.addColorStop(0.5, 'rgba(14, 165, 233, 0.4)');
      aura.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = aura;
      ctx.beginPath();
      ctx.arc(cx, cy, radius * 1.7, 0, 2 * Math.PI);
      ctx.fill();

      // 2. Back Orbit Ring 1 (behind planet)
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.36);
      ctx.beginPath();
      ctx.arc(0, 0, 57, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.lineWidth = 9;
      ctx.stroke();
      ctx.restore();

      // 3. Back Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.32);
      ctx.beginPath();
      ctx.arc(0, 0, 60, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.75)';
      ctx.lineWidth = 7;
      ctx.stroke();
      ctx.restore();

      // 4. Central 3D Vibrant Planet Body
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      
      const sphereGrad = ctx.createRadialGradient(
        cx - 10,
        cy - 12,
        2,
        cx,
        cy,
        radius
      );
      sphereGrad.addColorStop(0, '#ffffff');
      sphereGrad.addColorStop(0.2, '#38bdf8');
      sphereGrad.addColorStop(0.65, '#0284c7');
      sphereGrad.addColorStop(1, '#0369a1');

      ctx.fillStyle = sphereGrad;
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 20;
      ctx.fill();
      ctx.restore();

      // 5. White & Bright Pink 3D Surface Texture Motion
      for (let i = 0; i < 10; i++) {
        const phi = (i / 10) * Math.PI * 2;
        const xOff = Math.sin(angle + phi) * (radius * 0.72);
        const yOff = Math.cos((angle + phi) * 0.7) * (radius * 0.62);
        ctx.fillStyle = i % 2 === 0 ? '#f472b6' : '#ffffff';
        ctx.beginPath();
        ctx.arc(cx + xOff, cy + yOff, 4.5, 0, 2 * Math.PI);
        ctx.fill();
      }

      // 6. Front Orbit Ring 1 + Revolving Glowing Moon
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.36);
      ctx.beginPath();
      ctx.arc(0, 0, 57, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 9;
      ctx.shadowColor = '#ffffff';
      ctx.shadowBlur = 14;
      ctx.stroke();

      const moonX = Math.cos(angle * 1.5) * 57;
      const moonY = Math.sin(angle * 1.5) * 57;
      ctx.fillStyle = '#ffffff';
      ctx.shadowColor = '#00f0ff';
      ctx.shadowBlur = 16;
      ctx.beginPath();
      ctx.arc(moonX, moonY, 9, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();

      // 7. Front Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.32);
      ctx.beginPath();
      ctx.arc(0, 0, 60, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.95)';
      ctx.lineWidth = 7;
      ctx.stroke();
      ctx.restore();

      // Refresh link element href data stream
      link.href = canvas.toDataURL('image/png');
    };

    // Update at 110ms interval (~9 FPS)
    const intervalId = setInterval(updateFavicon, 110);

    return () => {
      clearInterval(intervalId);
    };
  }, []);

  return null;
}
