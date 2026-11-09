interface RiskScoreGaugeProps {
  score: number;
  size?: number;
}

export default function RiskScoreGauge({ score, size = 180 }: RiskScoreGaugeProps) {
  const clampedScore = Math.max(0, Math.min(100, score));

  // SVG arc parameters
  const strokeWidth = 14;
  const radius = (size - strokeWidth) / 2;
  const cx = size / 2;
  const cy = size / 2;

  // We draw a semicircular arc (180 degrees) from left to right
  const startAngle = 180; // left side
  const endAngle = 0; // right side
  const totalArc = Math.PI; // 180 degrees
  const scoreAngle = (clampedScore / 100) * totalArc;

  // Helper to convert angle to SVG coordinates (angle in radians from right/3-o'clock, going CCW for our semicircle)
  const polarToCartesian = (angleDeg: number) => {
    const angleRad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(angleRad),
      y: cy - radius * Math.sin(angleRad),
    };
  };

  // Background arc path (full semicircle top half)
  const bgStart = polarToCartesian(startAngle);
  const bgEnd = polarToCartesian(endAngle);
  const bgArc = `M ${bgStart.x} ${bgStart.y} A ${radius} ${radius} 0 0 1 ${bgEnd.x} ${bgEnd.y}`;

  // Score arc path
  const scoreDeg = startAngle - (clampedScore / 100) * 180;
  const scoreEnd = polarToCartesian(scoreDeg);
  const largeArcFlag = clampedScore > 50 ? 1 : 0;
  const scoreArc =
    clampedScore > 0
      ? `M ${bgStart.x} ${bgStart.y} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${scoreEnd.x} ${scoreEnd.y}`
      : '';

  // Color based on score
  const getColor = (): string => {
    if (clampedScore <= 30) return '#10b981'; // emerald-500
    if (clampedScore <= 60) return '#f59e0b'; // amber-500
    return '#ef4444'; // red-500
  };

  const getLabel = (): string => {
    if (clampedScore <= 30) return 'Low Risk';
    if (clampedScore <= 60) return 'Medium Risk';
    return 'High Risk';
  };

  const getLabelColor = (): string => {
    if (clampedScore <= 30) return 'text-emerald-400';
    if (clampedScore <= 60) return 'text-amber-400';
    return 'text-red-400';
  };

  const color = getColor();

  // Gradient ID unique per instance
  const gradientId = `gauge-gradient-${score}`;

  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size / 2 + 30} viewBox={`0 0 ${size} ${size / 2 + 30}`}>
        <defs>
          <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="50%" stopColor="#f59e0b" />
            <stop offset="100%" stopColor="#ef4444" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="3" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* Background arc */}
        <path
          d={bgArc}
          fill="none"
          stroke="#1e293b"
          strokeWidth={strokeWidth}
          strokeLinecap="round"
        />

        {/* Score arc */}
        {scoreArc && (
          <path
            d={scoreArc}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            filter="url(#glow)"
            className="transition-all duration-1000 ease-out"
          />
        )}

        {/* Score number in center */}
        <text
          x={cx}
          y={cy - 10}
          textAnchor="middle"
          dominantBaseline="central"
          className="font-bold"
          fill={color}
          fontSize={size / 4}
        >
          {clampedScore}
        </text>

        {/* /100 label */}
        <text
          x={cx}
          y={cy + 15}
          textAnchor="middle"
          dominantBaseline="central"
          fill="#64748b"
          fontSize={size / 12}
        >
          / 100
        </text>
      </svg>
      <p className={`text-sm font-semibold mt-1 ${getLabelColor()}`}>{getLabel()}</p>
    </div>
  );
}
