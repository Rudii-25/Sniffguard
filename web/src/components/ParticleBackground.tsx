import { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import * as THREE from 'three';

const PARTICLE_COUNT = 600;
const GRID_SIZE = 20;

function ParticleField() {
  const meshRef = useRef<THREE.Points>(null);
  const mouseRef = useRef({ x: 0, y: 0 });

  const { positions, basePositions } = useMemo(() => {
    const positions = new Float32Array(PARTICLE_COUNT * 3);
    const basePositions = new Float32Array(PARTICLE_COUNT * 3);
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const x = (Math.random() - 0.5) * GRID_SIZE;
      const y = (Math.random() - 0.5) * GRID_SIZE;
      const z = (Math.random() - 0.5) * 6;
      positions[i * 3] = x;
      positions[i * 3 + 1] = y;
      positions[i * 3 + 2] = z;
      basePositions[i * 3] = x;
      basePositions[i * 3 + 1] = y;
      basePositions[i * 3 + 2] = z;
    }
    return { positions, basePositions };
  }, []);

  const colors = useMemo(() => {
    const cols = new Float32Array(PARTICLE_COUNT * 3);
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const t = Math.random();
      // Blend between cyan (0, 0.95, 1) and blue (0.31, 0.67, 1)
      cols[i * 3] = THREE.MathUtils.lerp(0, 0.31, t);
      cols[i * 3 + 1] = THREE.MathUtils.lerp(0.95, 0.67, t);
      cols[i * 3 + 2] = 1;
    }
    return cols;
  }, []);

  const sizes = useMemo(() => {
    const s = new Float32Array(PARTICLE_COUNT);
    for (let i = 0; i < PARTICLE_COUNT; i++) {
      s[i] = Math.random() * 2 + 0.5;
    }
    return s;
  }, []);

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    const time = clock.getElapsedTime();
    const pos = meshRef.current.geometry.attributes.position.array as Float32Array;

    for (let i = 0; i < PARTICLE_COUNT; i++) {
      const bx = basePositions[i * 3];
      const by = basePositions[i * 3 + 1];
      const bz = basePositions[i * 3 + 2];

      pos[i * 3] = bx + Math.sin(time * 0.3 + bx * 0.5) * 0.15;
      pos[i * 3 + 1] = by + Math.cos(time * 0.2 + by * 0.5) * 0.15;
      pos[i * 3 + 2] = bz + Math.sin(time * 0.15 + bz) * 0.1;
    }

    meshRef.current.geometry.attributes.position.needsUpdate = true;
    meshRef.current.rotation.z = time * 0.02;
  });

  return (
    <points ref={meshRef}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          args={[positions, 3]}
        />
        <bufferAttribute
          attach="attributes-color"
          args={[colors, 3]}
        />
      </bufferGeometry>
      <pointsMaterial
        size={0.04}
        vertexColors
        transparent
        opacity={0.6}
        sizeAttenuation
        depthWrite={false}
        blending={THREE.AdditiveBlending}
      />
    </points>
  );
}

function GridMesh() {
  const meshRef = useRef<THREE.LineSegments>(null);

  const geometry = useMemo(() => {
    const geo = new THREE.BufferGeometry();
    const vertices: number[] = [];
    const step = 2;
    const half = 10;

    for (let x = -half; x <= half; x += step) {
      for (let y = -half; y <= half; y += step) {
        // horizontal lines
        if (x + step <= half) {
          vertices.push(x, y, 0, x + step, y, 0);
        }
        // vertical lines
        if (y + step <= half) {
          vertices.push(x, y, 0, x, y + step, 0);
        }
      }
    }

    geo.setAttribute('position', new THREE.Float32BufferAttribute(vertices, 3));
    return geo;
  }, []);

  useFrame(({ clock }) => {
    if (!meshRef.current) return;
    meshRef.current.rotation.x = Math.PI * 0.4 + Math.sin(clock.getElapsedTime() * 0.1) * 0.05;
    meshRef.current.rotation.z = clock.getElapsedTime() * 0.015;
  });

  return (
    <lineSegments ref={meshRef} geometry={geometry} position={[0, -2, -4]} rotation={[Math.PI * 0.4, 0, 0]}>
      <lineBasicMaterial color="#4facfe" transparent opacity={0.06} />
    </lineSegments>
  );
}

export function ParticleBackground() {
  return (
    <div className="absolute inset-0 z-0">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 60 }}
        dpr={[1, 1.5]}
        gl={{ antialias: false, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <ParticleField />
        <GridMesh />
      </Canvas>
    </div>
  );
}
