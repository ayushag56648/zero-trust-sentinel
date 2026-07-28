"use client"

import { Card } from "@/components/ui/card"
import { Github } from "lucide-react"

export function GithubCtaPanel() {
  return (
    <Card 
      className="glass-card p-6 group cursor-pointer relative overflow-hidden transition-all duration-500 hover:border-[#5b5fcf]/50 hover:shadow-[0_0_30px_rgba(91,95,207,0.15)]"
      onClick={() => window.open('https://github.com/ayushag56648', '_blank')}
    >
      <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
        
        {/* Text Section */}
        <div className="flex-shrink-0 text-center md:text-left z-20">
          <h3 className="text-xl font-semibold text-foreground">Curious about the creator?</h3>
        </div>

        {/* 3D Visual Scene */}
        <div className="flex-1 w-full h-[100px] relative flex items-center justify-center md:justify-end overflow-hidden perspective-[1000px]">
          
          {/* Subtle background grid/glow */}
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(91,95,207,0.15)_0%,transparent_70%)] opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" />
          
          <div className="relative w-full max-w-[400px] h-full flex items-center justify-between" style={{ transformStyle: 'preserve-3d' }}>
            
            {/* Left side: Metallic rail/launch mechanism */}
            <div className="relative w-[50px] h-[36px] bg-gradient-to-r from-[#111114] to-[#1f1f23] border border-[#2a2a35] rounded-l-md flex flex-col justify-between p-1 z-20 shadow-[8px_0_15px_rgba(0,0,0,0.5)] transform -rotate-y-[15deg]">
              <div className="h-[2px] bg-[#080809] rounded-full w-full" />
              {/* Blue plasma glow on hover */}
              <div className="absolute top-1/2 -translate-y-1/2 right-0 w-[4px] h-[16px] bg-[#5b5fcf]/20 rounded-l-sm group-hover:bg-[#5b5fcf] group-hover:shadow-[0_0_12px_#5b5fcf] transition-all duration-500" />
              <div className="h-[2px] bg-[#080809] rounded-full w-full" />
            </div>

            {/* Center: Blue energy spike/beam */}
            <div className="flex-1 h-[2px] relative overflow-hidden flex items-center z-10 -mx-1">
              <div className="absolute inset-0 bg-[#2a2a35]" />
              <div 
                className="h-[2px] w-full bg-[#5b5fcf] shadow-[0_0_10px_#5b5fcf] transform -translate-x-[101%] group-hover:translate-x-0 transition-transform duration-[800ms] ease-out" 
              />
            </div>

            {/* Right side: 3D Octocat (GitHub) */}
            <div className="relative z-20 transform transition-transform duration-500 group-hover:scale-110 group-hover:rotate-[15deg] group-hover:drop-shadow-[0_0_20px_rgba(91,95,207,0.4)]">
              <div className="w-[56px] h-[56px] bg-[#1a1a1f] border border-[#2a2a35] rounded-xl flex items-center justify-center relative overflow-hidden shadow-[0_10px_30px_rgba(0,0,0,0.5)] transform rotate-y-[-5deg] group-hover:rotate-y-0 transition-transform duration-500">
                <div className="absolute inset-0 bg-gradient-to-br from-transparent to-[#5b5fcf]/5 group-hover:to-[#5b5fcf]/20 transition-colors duration-500" />
                <Github className="w-7 h-7 text-[#71717a] relative z-10 transition-colors duration-500 group-hover:text-[#f4f4f5]" />
                
                {/* 3D edge highlight */}
                <div className="absolute inset-x-0 top-0 h-[1px] bg-gradient-to-r from-transparent via-white/10 to-transparent" />
              </div>
            </div>

          </div>
        </div>

      </div>
    </Card>
  )
}
