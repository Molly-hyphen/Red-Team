import React, { useState } from 'react';
import { ChevronDown, ChevronUp, Lightbulb } from 'lucide-react';

interface PlainEnglishBannerProps {
  title: string;
  summary: string;
  points?: Array<{ label: string; desc: string }>;
  defaultOpen?: boolean;
}

export const PlainEnglishBanner: React.FC<PlainEnglishBannerProps> = ({
  title,
  summary,
  points = [],
  defaultOpen = true,
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="bg-gradient-to-r from-sky-950/40 via-[#0a1b38] to-blue-950/30 border border-sky-500/25 rounded-2xl p-4 shadow-md transition-all font-sans w-full min-w-0">
      <div
        className="flex items-center justify-between cursor-pointer select-none gap-2"
        onClick={() => setIsOpen(!isOpen)}
      >
        <div className="flex items-center space-x-3 min-w-0">
          <div className="p-2 rounded-xl bg-sky-500/15 border border-sky-400/30 text-sky-300 shadow-sm shadow-sky-500/10 shrink-0">
            <Lightbulb className="w-4 h-4" />
          </div>
          <div className="min-w-0">
            <h3 className="text-xs font-bold text-sky-200 tracking-wide">{title}</h3>
            <p className="text-[11px] text-slate-300 mt-0.5 break-words">{summary}</p>
          </div>
        </div>

        <button
          type="button"
          className="text-slate-400 hover:text-sky-200 p-1.5 rounded-lg hover:bg-[#102447] transition-colors shrink-0"
        >
          {isOpen ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>
      </div>

      {isOpen && points.length > 0 && (
        <div className="mt-3 pt-3 border-t border-[#162f59] grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {points.map((p, idx) => (
            <div key={idx} className="bg-[#071329] p-3 rounded-xl border border-[#142d54] text-xs shadow-inner">
              <div className="font-semibold text-sky-300 flex items-center space-x-1.5 mb-1">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shadow-sm shadow-sky-400" />
                <span>{p.label}</span>
              </div>
              <p className="text-[11px] text-slate-300 leading-relaxed">{p.desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
export default PlainEnglishBanner;
