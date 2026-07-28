"use client"

import React, { useEffect, useRef, useState } from "react"

export function InteractivePdfDisarm() {
  const [phase, setPhase] = useState<0 | 1 | 2 | 3 | 4>(0)
  // 0: Idle Red, 1: Exploding, 2: Sweeping, 3: Reforming, 4: Idle Green
  const canvasRef = useRef<HTMLCanvasElement>(null)
  
  const stateRef = useRef({
    phase: 0,
    particles: [] as any[],
    sweepX: 0,
    time: 0,
  })

  // Initialize particles and animation loop
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animationFrameId: number

    const w = 320
    const h = 420
    const cw = 500
    const ch = 600
    canvas.width = cw
    canvas.height = ch

    const offsetX = (cw - w) / 2
    const offsetY = (ch - h) / 2

    // Create particles
    const p = []
    for (let i = 0; i < 150; i++) {
      const rx = Math.random() * w
      const ry = Math.random() * h
      const isRed = Math.random() > 0.8 || ry < 15 // top border is red
      p.push({
        ox: offsetX + rx,
        oy: offsetY + ry,
        x: offsetX + rx,
        y: offsetY + ry,
        vx: 0,
        vy: 0,
        color: isRed ? '#ef4444' : '#3f3f46',
        targetColor: isRed ? '#10b981' : '#3f3f46',
        size: Math.random() * 3 + 2,
        isSwept: false
      })
    }
    stateRef.current.particles = p

    let lastTime = performance.now()

    const render = (time: number) => {
      const dt = Math.min((time - lastTime) / 1000, 0.1) // Cap dt to avoid huge jumps
      lastTime = time
      stateRef.current.time = time

      ctx.clearRect(0, 0, cw, ch)
      const s = stateRef.current

      if (s.phase > 0 && s.phase < 4) {
        for (let i = 0; i < s.particles.length; i++) {
          const pt = s.particles[i]

          if (s.phase === 1) {
            // Explode
            pt.x += pt.vx * dt * 60
            pt.y += pt.vy * dt * 60
            pt.vx *= 0.94 
            pt.vy *= 0.94
          } else if (s.phase === 2) {
            // Sweep
            pt.x += pt.vx * dt * 60
            pt.y += pt.vy * dt * 60
            pt.vx *= 0.90
            pt.vy *= 0.90
            
            if (!pt.isSwept && pt.x < s.sweepX) {
              pt.isSwept = true
              pt.color = pt.targetColor
              // Give a little pop when swept
              pt.vx += (Math.random() - 0.5) * 5
              pt.vy += (Math.random() - 0.5) * 5
            }
          } else if (s.phase === 3) {
            // Reform
            const dx = pt.ox - pt.x
            const dy = pt.oy - pt.y
            pt.x += dx * 10 * dt
            pt.y += dy * 10 * dt
          }

          ctx.fillStyle = pt.color
          ctx.fillRect(pt.x, pt.y, pt.size, pt.size)
        }

        if (s.phase === 2) {
          // Draw sweep line
          s.sweepX += 1200 * dt
          ctx.shadowBlur = 15
          ctx.shadowColor = '#06b6d4'
          ctx.fillStyle = '#06b6d4'
          ctx.fillRect(s.sweepX, 0, 3, ch)
          ctx.shadowBlur = 0
          
          if (s.sweepX > cw + 50) {
            s.phase = 3
            setPhase(3)
            setTimeout(() => {
              s.phase = 4
              setPhase(4)
            }, 600)
          }
        }
      }

      animationFrameId = requestAnimationFrame(render)
    }
    
    animationFrameId = requestAnimationFrame(render)
    return () => cancelAnimationFrame(animationFrameId)
  }, [])

  const handleMouseEnter = () => {
    const s = stateRef.current
    if (s.phase === 0) {
      s.phase = 1
      setPhase(1)
      
      const cw = 500
      const ch = 600
      s.particles.forEach(pt => {
        const dx = pt.x - cw / 2
        const dy = pt.y - ch / 2
        const dist = Math.sqrt(dx*dx + dy*dy) || 1
        pt.vx = (dx / dist) * (Math.random() * 25 + 10)
        pt.vy = (dy / dist) * (Math.random() * 25 + 10)
      })

      // Start sweep after 0.8s
      setTimeout(() => {
        s.phase = 2
        s.sweepX = -50
        setPhase(2)
      }, 800)
    }
  }

  return (
    <div 
      className="w-full lg:w-1/2 flex justify-center lg:justify-end items-center group perspective-[1000px] perspective-origin-[50%_40%]"
      onMouseEnter={handleMouseEnter}
    >
      <div className="relative w-[500px] h-[600px] flex items-center justify-center">
        
        {/* Canvas Layer */}
        <canvas 
          ref={canvasRef}
          className="absolute inset-0 z-10 pointer-events-none"
          style={{
            opacity: (phase > 0 && phase < 4) ? 1 : 0
          }}
        />

        {/* DOM Cards */}
        <div 
          className="relative z-0 transition-transform duration-700 w-[320px] h-[420px]"
          style={{
            transform: phase === 0 ? 'rotateX(8deg) rotateY(-18deg) rotateZ(1deg)' : 
                       phase === 4 ? 'rotateX(4deg) rotateY(-12deg) rotateZ(0deg)' : 
                       'rotateX(0deg) rotateY(0deg) rotateZ(0deg)',
            animation: phase === 0 ? 'float-red 4s ease-in-out infinite' : 
                       phase === 4 ? 'float-green 4s ease-in-out infinite' : 'none'
          }}
        >
          <style dangerouslySetInnerHTML={{__html: `
            @keyframes float-red {
              0%, 100% { transform: translateY(0px) rotateX(8deg) rotateY(-18deg) rotateZ(1deg); }
              50% { transform: translateY(-15px) rotateX(8deg) rotateY(-18deg) rotateZ(1deg); }
            }
            @keyframes float-green {
              0%, 100% { transform: translateY(0px) rotateX(4deg) rotateY(-12deg) rotateZ(0deg); }
              50% { transform: translateY(-15px) rotateX(4deg) rotateY(-12deg) rotateZ(0deg); }
            }
          `}} />

          {/* RED IDLE CARD */}
          <div 
            className="absolute inset-0 bg-[#1a1a1f] border border-[#2a2a35] rounded-[4px] transition-opacity duration-200"
            style={{
              opacity: phase === 0 ? 1 : 0,
              boxShadow: '0 0 0 1px #2a2a35, 0 20px 60px rgba(0,0,0,0.8), 0 0 120px rgba(239,68,68,0.08), inset 0 1px 0 rgba(255,255,255,0.04)'
            }}
          >
            <div className="h-[3px] rounded-t-[4px] bg-gradient-to-r from-[#ef4444] to-[#dc2626]" />
            <div className="absolute left-0 right-0 h-[1px] bg-[#5b5fcf] opacity-40 animate-[scan-sweep_3s_linear_infinite] shadow-[0_0_8px_#5b5fcf]" />
            
            <div className="px-[24px] pt-[20px] pb-[16px]">
              <div className="w-[40px] h-[40px] bg-[#ef4444]/10 border border-[#ef4444]/20 rounded-[6px] flex items-center justify-center mb-[12px]">
                <div className="w-[18px] h-[22px] relative flex flex-col justify-between py-[2px]">
                  <div className="h-[2px] bg-[#ef4444] rounded-[1px] w-full" />
                  <div className="h-[2px] bg-[#ef4444] rounded-[1px] w-full" />
                  <div className="h-[2px] bg-[#ef4444] rounded-[1px] w-[70%]" />
                </div>
              </div>
              <div className="h-[10px] bg-[#2a2a35] rounded-[2px] mb-[8px]" />
              <div className="h-[8px] bg-[#222228] rounded-[2px] w-[70%]" />
            </div>

            <div className="px-[24px]">
              <div className="bg-[#ef4444]/[0.06] border border-[#ef4444]/15 rounded-[4px] px-[10px] py-[8px] mb-[6px] flex items-center gap-[8px]">
                <div className="w-[6px] h-[6px] rounded-full bg-[#ef4444] shrink-0" />
                <div className="h-[7px] bg-[#2a2a35] rounded-[2px] flex-1" />
              </div>
              <div className="bg-[#ef4444]/[0.06] border border-[#ef4444]/15 rounded-[4px] px-[10px] py-[8px] mb-[6px] flex items-center gap-[8px]">
                <div className="w-[6px] h-[6px] rounded-full bg-[#f59e0b] shrink-0" />
                <div className="h-[7px] bg-[#2a2a35] rounded-[2px] flex-1" />
              </div>
              <div className="mt-[16px]">
                <div className="h-[7px] bg-[#222228] rounded-[2px] mb-[6px]" />
                <div className="h-[7px] bg-[#222228] rounded-[2px] mb-[6px] w-[85%]" />
                <div className="h-[7px] bg-[#222228] rounded-[2px] mb-[6px] w-[60%]" />
              </div>
              <div className="mt-[16px] bg-[#ef4444]/[0.08] border border-[#ef4444]/20 rounded-[6px] px-[14px] py-[10px] flex justify-between items-center">
                <span className="text-[#71717a] text-[11px] font-mono">Threat Score</span>
                <span className="text-[#ef4444] text-[14px] font-[600] font-mono">100 / 100</span>
              </div>
            </div>
          </div>

          {/* GREEN REFORMED CARD */}
          <div 
            className="absolute inset-0 bg-[#0f1f14] border border-[#10b981]/20 rounded-[4px] transition-opacity duration-700"
            style={{
              opacity: phase === 4 ? 1 : 0,
              boxShadow: '0 0 0 1px #16a34a, 0 20px 60px rgba(0,0,0,0.8), 0 0 120px rgba(16,185,129,0.1), inset 0 1px 0 rgba(255,255,255,0.04)'
            }}
          >
            <div className="h-[3px] bg-gradient-to-r from-[#10b981] to-[#059669] rounded-t-[4px]" />
            
            <div className="px-[24px] pt-[20px] pb-[16px]">
              <div className="w-[40px] h-[40px] bg-[#10b981]/10 border border-[#10b981]/20 rounded-[6px] flex items-center justify-center mb-[12px]">
                <div className="w-[18px] h-[22px] relative flex flex-col justify-between py-[2px]">
                  <div className="h-[2px] bg-[#10b981] rounded-[1px] w-full" />
                  <div className="h-[2px] bg-[#10b981] rounded-[1px] w-full" />
                  <div className="h-[2px] bg-[#10b981] rounded-[1px] w-[70%]" />
                </div>
              </div>
              <div className="h-[10px] bg-[#16a34a]/20 rounded-[2px] mb-[8px]" />
              <div className="h-[8px] bg-[#16a34a]/10 rounded-[2px] w-[70%]" />
            </div>

            <div className="px-[24px]">
              <div className="bg-[#10b981]/[0.06] border border-[#10b981]/15 rounded-[4px] px-[10px] py-[8px] mb-[6px] flex items-center gap-[8px]">
                <div className="w-[6px] h-[6px] rounded-full bg-[#10b981] shrink-0" />
                <div className="h-[7px] bg-[#16a34a]/30 rounded-[2px] flex-1" />
              </div>
              <div className="bg-[#10b981]/[0.06] border border-[#10b981]/15 rounded-[4px] px-[10px] py-[8px] mb-[6px] flex items-center gap-[8px]">
                <div className="w-[6px] h-[6px] rounded-full bg-[#10b981] shrink-0" />
                <div className="h-[7px] bg-[#16a34a]/30 rounded-[2px] flex-1" />
              </div>
              <div className="mt-[16px]">
                <div className="h-[7px] bg-[#10b981]/20 rounded-[2px] mb-[6px]" />
                <div className="h-[7px] bg-[#10b981]/20 rounded-[2px] mb-[6px] w-[85%]" />
                <div className="h-[7px] bg-[#10b981]/20 rounded-[2px] mb-[6px] w-[60%]" />
              </div>
              <div className="mt-[16px] bg-[#10b981]/[0.08] border border-[#10b981]/20 rounded-[6px] px-[14px] py-[10px] flex justify-between items-center">
                <span className="text-[#059669] text-[11px] font-mono">Threat Score</span>
                <span className="text-[#10b981] text-[14px] font-[600] font-mono">0 / 100 &bull; Disarmed</span>
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}
