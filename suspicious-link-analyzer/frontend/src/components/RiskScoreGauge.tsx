import React from 'react';

interface RiskScoreGaugeProps {
  score: number;
  size?: number;
}

export default function RiskScoreGauge({ score, size = 200 }: RiskScoreGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

  // Semicircle parameters
  // Coordinate space: 200 wide by 130 high
  // Center (100, 100), radius = 72, strokeWidth = 14
  // Arc length = PI * 72 ≈ 226.195
  const radius = 72;
  const strokeWidth = 14;
  const cx = 100;
  const cy = 100;
  const arcLength = Math.PI * radius; // ~226.195

  // Semicircle path from left (28, 100) to right (172, 100)
  const pathD = `M ${cx - radius} ${cy} A ${radius} ${radius} 0 0 1 ${cx + radius} ${cy}`;

  // Dashoffset: 0% score => arcLength, 100% score => 0
  const strokeDashoffset = arcLength * (1 - clampedScore / 100);

  // Colors & classification according to specification:
  // 0-29: Low risk (Green)
  // 30-69: Medium risk (Amber)
  // 70-100: High risk (Red)
  const getColor = (): string => {
    if (clampedScore < 30) return '#10b981'; // emerald-500
    if (clampedScore < 70) return '#f59e0b'; // amber-500
    return '#ef4444'; // red-500
  };

  const getLabel = (): string => {
    if (clampedScore < 30) return 'Low Risk';
    if (clampedScore < 70) return 'Medium Risk';
    return 'High Risk';
  };

  const getLabelClass = (): string => {
    if (clampedScore < 30) return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/80';
    if (clampedScore < 70) return 'text-amber-400 bg-amber-950/60 border-amber-800/80';
    return 'text-rose-400 bg-rose-950/60 border-rose-800/80';
  };

  const color = getColor();
  const filterId = `gauge-glow-${Math.round(score)}`;

  return (
    <div className="flex flex-col items-center select-none">
      <div className="relative" style={{ width: size, height: (size * 130) / 200 }}>
        <svg
          viewBox="0 0 200 130"
          className="w-full h-full overflow-visible"
        >
          <defs>
            <filter id={filterId} x="-20%" y="-20%" width="140%" height="140%">
              <feDropShadow dx="0" dy="0" stdDeviation="3.5" floodColor={color} floodOpacity="0.45" />
            </filter>
          </defs>

          {/* Background Track Arc */}
          <path
            d={pathD}
            fill="none"
            stroke="#1e293b"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />

          {/* Animated Value Arc */}
          {clampedScore > 0 && (
            <path
              d={pathD}
              fill="none"
              stroke={color}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={arcLength}
              strokeDashoffset={strokeDashoffset}
              filter={`url(#${filterId})`}
              style={{
                transition: 'stroke-dashoffset 0.9s cubic-bezier(0.4, 0, 0.2, 1), stroke 0.4s ease',
              }}
            />
          )}

          {/* Center Score Value */}
          <text
            x={cx}
            y={cy - 12}
            textAnchor="middle"
            dominantBaseline="central"
            fill={color}
            fontSize="34"
            fontWeight="800"
            fontFamily="ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif"
          >
            {clampedScore}
          </text>

          {/* Center "/ 100" Label */}
          <text
            x={cx}
            y={cy + 14}
            textAnchor="middle"
            dominantBaseline="central"
            fill="#64748b"
            fontSize="12"
            fontWeight="500"
            fontFamily="ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif"
          >
            / 100
          </text>
        </svg>
      </div>

      {/* Pill Badge with Risk Label */}
      <span className={`mt-2 px-3 py-0.5 rounded-full text-xs font-semibold border ${getLabelClass()}`}>
        {getLabel()}
      </span>
    </div>
  );
}
