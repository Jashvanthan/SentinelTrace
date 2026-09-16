// SentinelTrace Frontend — Live Animated 3D Favicon for Browser Tab

import { useEffect } from 'react';

export function AnimatedFavicon() {
  useEffect(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 32;
    canvas.height = 32;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let faviconLink = document.querySelector<HTMLLinkElement>("link[rel*='icon']");
    if (!faviconLink) {
      faviconLink = document.createElement('link');
      faviconLink.rel = 'shortcut icon';
      document.getElementsByTagName('head')[0].appendChild(faviconLink);
    }

    let angle = 0;
    let animationId: number;

    const drawFavicon = () => {
      angle += 0.04;
      ctx.clearRect(0, 0, 32, 32);

      const cx = 16;
      const cy = 16;
      const radius = 8;

      // 1. Back Ring
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 14, Math.PI, 2 * Math.PI);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.6)';
      ctx.lineWidth = 1.5;
      ctx.stroke();
      ctx.restore();

      // 2. Main 3D Sphere Body
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, 2 * Math.PI);
      const grad = ctx.createRadialGradient(cx - 2, cy - 2, 1, cx, cy, radius);
      grad.addColorStop(0, '#7dd3fc');
      grad.addColorStop(0.5, '#0ea5e9');
      grad.addColorStop(1, '#0284c7');
      ctx.fillStyle = grad;
      ctx.fill();

      // 3. Front Ring + Revolving Orbit Dot
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(-Math.PI / 6);
      ctx.scale(1, 0.35);
      ctx.beginPath();
      ctx.arc(0, 0, 14, 0, Math.PI);
      ctx.strokeStyle = '#ffffff';
      ctx.lineWidth = 1.8;
      ctx.stroke();

      const moonX = Math.cos(angle) * 14;
      const moonY = Math.sin(angle) * 14;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.arc(moonX, moonY, 1.8, 0, 2 * Math.PI);
      ctx.fill();
      ctx.restore();

      // Update browser tab icon data URL
      faviconLink!.href = canvas.toDataURL('image/png');
      animationId = requestAnimationFrame(drawFavicon);
    };

    drawFavicon();

    return () => {
      cancelAnimationFrame(animationId);
    };
  }, []);

  return null;
}
