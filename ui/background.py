"""
Interactive Cyber Background Canvas
Renders a lightweight particle/grid network behind the UI.
Pointer-events are completely disabled (pointer-events: none) so it never intercepts user clicks.
Respects prefers-reduced-motion and tab visibility.
"""

def get_background_html(enabled: bool = True) -> str:
    if not enabled:
        return ""
    
    return """
<div id="cyber-bg-container" style="position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; pointer-events: none; z-index: -1; overflow: hidden; opacity: 0.65;">
    <canvas id="cyber-canvas" style="display: block; width: 100%; height: 100%;"></canvas>
</div>
<script>
(function() {
    // Respect user OS setting for reduced motion
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        return;
    }

    const canvas = document.getElementById('cyber-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    let width, height;
    function resize() {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    // Particle pool (strictly capped to 60 for 60fps lightweight performance)
    const particleCount = 60;
    const particles = [];
    for (let i = 0; i < particleCount; i++) {
        particles.push({
            x: Math.random() * width,
            y: Math.random() * height,
            vx: (Math.random() - 0.5) * 0.45,
            vy: (Math.random() - 0.5) * 0.45,
            radius: Math.random() * 1.5 + 0.8
        });
    }

    let isVisible = true;
    document.addEventListener("visibilitychange", function() {
        isVisible = !document.hidden;
    });

    function draw() {
        if (!isVisible) {
            requestAnimationFrame(draw);
            return;
        }

        ctx.clearRect(0, 0, width, height);

        // Faint tactical cyber grid
        ctx.strokeStyle = "rgba(14, 116, 144, 0.05)";
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

        // Connect particles with cyan vectors
        for (let i = 0; i < particleCount; i++) {
            const p1 = particles[i];
            p1.x += p1.vx;
            p1.y += p1.vy;

            if (p1.x < 0) p1.x = width;
            if (p1.x > width) p1.x = 0;
            if (p1.y < 0) p1.y = height;
            if (p1.y > height) p1.y = 0;

            // Draw particle node
            ctx.fillStyle = "rgba(0, 242, 254, 0.5)";
            ctx.beginPath();
            ctx.arc(p1.x, p1.y, p1.radius, 0, Math.PI * 2);
            ctx.fill();

            // Inter-node links
            for (let j = i + 1; j < particleCount; j++) {
                const p2 = particles[j];
                const dx = p1.x - p2.x;
                const dy = p1.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 110) {
                    const alpha = (1 - dist / 110) * 0.18;
                    ctx.strokeStyle = `rgba(0, 242, 254, ${alpha})`;
                    ctx.beginPath();
                    ctx.moveTo(p1.x, p1.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.stroke();
                }
            }
        }

        requestAnimationFrame(draw);
    }
    draw();
})();
</script>
"""

def render_background(enabled: bool = True):
    """Safely renders the animated cyber canvas in Streamlit."""
    import streamlit as st
    try:
        html = get_background_html(enabled=enabled)
        if html:
            if hasattr(st, "iframe"):
                st.iframe(html, height=1, width=1)  # replaces deprecated components.v1.html
            else:
                st.components.v1.html(html, height=0, width=0)
    except Exception:
        pass
