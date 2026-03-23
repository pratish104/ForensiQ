const BADGE_COLORS = {
  green: "bg-green-100 text-green-700",
  amber: "bg-amber-100 text-amber-700",
  red:   "bg-red-100   text-red-700",
  blue:  "bg-blue-100  text-blue-700",
  gray:  "bg-gray-100  text-gray-600",
};

export default function TopBar({ title, subtitle, badge, actions }) {
  return (
    <div className="sticky top-0 z-10 bg-white border-b border-gray-100 px-6 py-3 flex items-center justify-between">
      <div>
        <div className="flex items-center gap-2">
          <h1 className="text-base font-semibold text-gray-900">{title}</h1>
          {badge && (
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${BADGE_COLORS[badge.color]}`}>
              {badge.label}
            </span>
          )}
        </div>
        {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}