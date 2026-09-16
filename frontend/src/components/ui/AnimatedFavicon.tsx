// SentinelTrace Frontend — Live 3D Animated Browser Tab Favicon Icon

import { useEffect } from 'react';

export function AnimatedFavicon() {
  useEffect(() => {
    // 64x64 canvas for high sharpness on browser tab icons
    const canvas = document.createElement('canvas');
    canvas.width = 64;
    canvas.height = 64;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Remove existing static favicon link tags
    const existingIcons = document.querySelectorAll("link[rel*='icon']");
    existingIcons.forEach((el) => el.remove());

    // Create fresh dynamic favicon link element
    let link = document.createElement('link');
    link.id = 'dynamic-3d-favicon';
    link.rel = 'icon';
    link.type = 'image/png';
    document.head.appendChild(link);

    let angle = 0;

    const updateFavicon = () => {
      angle += 0.15;
      ctx.clearRect(0, 0, 64, 64);

      const cx = 32;
      const cy = 32;
      const radius = 16;

      // 1. Back Orbit Ring 1
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 28, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.7)';
      ctx.lineWidth = 3.5;
      ctx.stroke();
      ctx.restore();

      // 2. Back Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 30, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(125, 211, 252, 0.5)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.restore();

      // 3. Central 3D Sphere Body
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      const grad = ctx.createRadialGradient(cx - 5, cy - 5, 2, cx, cy, radius);
      grad.addColorStop(0, '#7dd3fc');
      grad.addColorStop(0.5, '#0ea5e9');
      grad.addColorStop(1, '#0284c7');
      ctx.fillStyle = grad;
      ctx.fill();

      // 4. White & Pink 3D Speckles on Planet Surface
      for (let i = 0; i < 8; i++) {
        const phi = (i / 8) * Math.PI * 2;
        const xOff = Math.sin(angle + phi) * (radius * 0.7);
        const yOff = Math.cos((angle + phi) * 0.7) * (radius * 0.6);
        ctx.fillStyle = i % 2 === 0 ? '#f472b6' : '#ffffff';
        ctx.beginPath();
        ctx.arc(cx + xOff, cy + yOff, 2, 0, 2 * Math.PI);
        ctx.fill();
      }

      // 5. Front Orbit Ring 1 + Revolving Satellite Moon
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 28, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 3.5;
      ctx.stroke();

      const moonX = Math.cos(angle * 1.5) * 28;
      const moonY = Math.sin(angle * 1.5) * 28;
      ctx.fillStyle = '#bae6fd';
      ctx.beginPath();
      ctx.arc(moonX, moonY, 4, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();

      // 6. Front Orbit Ring 2
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(Math.PI / 4);
      ctx.scale(1, 0.3);
      ctx.beginPath();
      ctx.arc(0, 0, 30, 0, Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
      ctx.lineWidth = 2.5;
      ctx.stroke();
      ctx.restore();

      // Refresh link element to force browser tab to re-render favicon
      const dataUrl = canvas.toDataURL('image/png');
      link.href = dataUrl;
    };

    // Update at 120ms interval (~8 FPS) — optimal rate for browser tab favicons
    const intervalId = setInterval(updateFavicon, 120);

    return () => {
      clearInterval(intervalId);
    };
  }, []);

  return null;
}
