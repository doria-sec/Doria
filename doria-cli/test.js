const WIDTH = 80;
const HEIGHT = 24;
const PARTICLE_COUNT = 60;
const GRAVITY = 0.15;
const BOUNCE = 0.7;

class Particle {
    constructor() {
        this.x = Math.random() * WIDTH;
        this.y = Math.random() * HEIGHT;
        this.vx = (Math.random() - 0.5) * 1.5;
        this.vy = Math.random() * -2;
    }

    update() {
        this.vy += GRAVITY;
        this.x += this.vx;
        this.y += this.vy;

        if (this.x <= 0 || this.x >= WIDTH - 1) {
            this.vx *= -BOUNCE;
            this.x = Math.max(0, Math.min(WIDTH - 1, this.x));
        }

        if (this.y >= HEIGHT - 1) {
            this.vy *= -BOUNCE;
            this.y = HEIGHT - 1;
        }
    }
}

const particles = Array.from({ length: PARTICLE_COUNT }, () => new Particle());

function render() {
    const grid = Array.from({ length: HEIGHT }, () =>
        Array.from({ length: WIDTH }, () => ' ')
    );

    for (const p of particles) {
        const x = Math.floor(p.x);
        const y = Math.floor(p.y);
        if (grid[y] && grid[y][x]) {
            grid[y][x] = '*';
        }
    }

    console.clear();
    console.log(grid.map(row => row.join('')).join('\n'));
}


setInterval(() => {
    particles.forEach(p => p.update());
    render();
}, 50);