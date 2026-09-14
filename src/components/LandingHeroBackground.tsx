import React, { useEffect, useRef } from 'react';

export const LandingHeroBackground: React.FC = () => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;

    const getValidWidth = (): number => {
      const containerW = canvas.parentElement?.clientWidth || canvas.clientWidth || window.innerWidth || 1200;
      return Math.max(10, Math.floor(containerW));
    };

    const getValidHeight = (): number => {
      const containerH = canvas.parentElement?.clientHeight || canvas.clientHeight || window.innerHeight || 800;
      return Math.max(10, Math.floor(containerH));
    };

    let width = (canvas.width = getValidWidth());
    let height = (canvas.height = getValidHeight());

    const handleResize = () => {
      if (!canvas) return;
      const newW = getValidWidth();
      const newH = getValidHeight();
      if (newW > 0 && newH > 0 && (canvas.width !== newW || canvas.height !== newH)) {
        canvas.width = newW;
        canvas.height = newH;
        width = newW;
        height = newH;
      }
    };

    let resizeObserver: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined') {
      resizeObserver = new ResizeObserver(() => {
        handleResize();
      });
      if (canvas.parentElement) {
        resizeObserver.observe(canvas.parentElement);
      } else {
        resizeObserver.observe(canvas);
      }
    }

    window.addEventListener('resize', handleResize);

    // Particle nodes for cyber mesh
    const particleCount = Math.min(width > 768 ? 60 : 30, 80);
    const particles: {
      x: number;
      y: number;
      vx: number;
      vy: number;
      radius: number;
      alpha: number;
      pulseSpeed: number;
    }[] = [];

    for (let i = 0; i < particleCount; i++) {
      particles.push({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
        radius: Math.random() * 2 + 1,
        alpha: Math.random() * 0.5 + 0.2,
        pulseSpeed: Math.random() * 0.02 + 0.005,
      });
    }

    // Interactive mouse parallax
    let mouseX = width / 2;
    let mouseY = height / 2;
    const handleMouseMove = (e: MouseEvent) => {
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      if (Number.isFinite(x) && Number.isFinite(y)) {
        mouseX = x;
        mouseY = y;
      }
    };
    window.addEventListener('mousemove', handleMouseMove);

    let scanlineY = 0;

    const render = () => {
      if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
        animationFrameId = requestAnimationFrame(render);
        return;
      }

      ctx.clearRect(0, 0, width, height);

      // Subtle cyber grid
      ctx.strokeStyle = 'rgba(2, 132, 199, 0.04)';
      ctx.lineWidth = 1;
      const gridSize = 48;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Center radial glow
      const cx = width / 2;
      const cy = height / 2;
      const outerRadius = Math.max(width, height) * 0.7;
      if (Number.isFinite(cx) && Number.isFinite(cy) && Number.isFinite(outerRadius) && outerRadius > 50) {
        try {
          const radialGlow = ctx.createRadialGradient(cx, cy, 50, cx, cy, outerRadius);
          radialGlow.addColorStop(0, 'rgba(2, 132, 199, 0.12)');
          radialGlow.addColorStop(0.4, 'rgba(14, 165, 233, 0.05)');
          radialGlow.addColorStop(0.8, 'rgba(99, 102, 241, 0.02)');
          radialGlow.addColorStop(1, 'transparent');
          ctx.fillStyle = radialGlow;
          ctx.fillRect(0, 0, width, height);
        } catch {
          // Ignore canvas gradient error if context invalid
        }
      }

      // Subtle horizontal scanline beam
      if (!Number.isFinite(scanlineY)) {
        scanlineY = 0;
      }
      if (height > 0) {
        scanlineY = (scanlineY + 1.2) % height;
      } else {
        scanlineY = 0;
      }

      const yStart = scanlineY - 40;
      const yEnd = scanlineY + 40;
      if (Number.isFinite(yStart) && Number.isFinite(yEnd)) {
        try {
          const scanGradient = ctx.createLinearGradient(0, yStart, 0, yEnd);
          scanGradient.addColorStop(0, 'rgba(56, 189, 248, 0)');
          scanGradient.addColorStop(0.5, 'rgba(56, 189, 248, 0.05)');
          scanGradient.addColorStop(1, 'rgba(56, 189, 248, 0)');
          ctx.fillStyle = scanGradient;
          ctx.fillRect(0, yStart, width, 80);
        } catch {
          // Ignore gradient creation failure on non-finite values
        }
      }

      // Update & Draw particles
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        if (!Number.isFinite(p.x)) p.x = Math.random() * width;
        if (!Number.isFinite(p.y)) p.y = Math.random() * height;

        p.x += p.vx;
        p.y += p.vy;

        // Bounce from borders
        if (p.x < 0 || p.x > width) p.vx *= -1;
        if (p.y < 0 || p.y > height) p.vy *= -1;

        // Alpha pulse
        p.alpha += Math.sin(Date.now() * p.pulseSpeed) * 0.01;
        p.alpha = Math.max(0.15, Math.min(0.7, p.alpha));

        // Draw particle node
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(56, 189, 248, ${p.alpha})`;
        ctx.shadowBlur = 8;
        ctx.shadowColor = '#38bdf8';
        ctx.fill();
        ctx.shadowBlur = 0;

        // Draw connections to nearby particles
        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);

          if (Number.isFinite(dist) && dist > 0 && dist < 130) {
            const lineAlpha = (1 - dist / 130) * 0.18;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = `rgba(14, 165, 233, ${Math.max(0, Math.min(1, lineAlpha))})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
          }
        }

        // Connection to mouse position
        if (Number.isFinite(mouseX) && Number.isFinite(mouseY)) {
          const mdx = p.x - mouseX;
          const mdy = p.y - mouseY;
          const mdist = Math.sqrt(mdx * mdx + mdy * mdy);
          if (Number.isFinite(mdist) && mdist > 0 && mdist < 160) {
            const mAlpha = (1 - mdist / 160) * 0.25;
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(mouseX, mouseY);
            ctx.strokeStyle = `rgba(99, 102, 241, ${Math.max(0, Math.min(1, mAlpha))})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      if (resizeObserver) {
        resizeObserver.disconnect();
      }
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 pointer-events-none w-full h-full z-0 opacity-80"
    />
  );
};
