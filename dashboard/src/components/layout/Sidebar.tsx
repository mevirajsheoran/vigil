import { NavLink } from "react-router-dom";

/*
Sidebar navigation for the dashboard.

WHY NavLink instead of a regular <a> tag?
NavLink automatically adds the "active" class when the URL matches
the link's to prop. This lets us style the currently selected page.

We use Font Awesome icons — you'll see them in the browser as 📊, 🔍, etc.
*/
const links = [
  { to: "/", label: "Overview", icon: "📊" },
  { to: "/fingerprints", label: "Fingerprints", icon: "🔍" },
  { to: "/attacks", label: "Attacks", icon: "🛡️" },
  { to: "/analytics", label: "Analytics", icon: "📈" },
  { to: "/live", label: "Live Feed", icon: "🔴" },
];

export default function Sidebar() {
  return (
    <aside className="w-64 bg-gray-900 border-r border-gray-800 p-6">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-white">Vigil</h1>
        <p className="text-xs text-gray-500 mt-1">API Abuse Detection</p>
      </div>

      <nav className="space-y-1">
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg transition-colors ${
                isActive
                  ? "bg-blue-600/20 text-blue-400"
                  : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
              }`
            }
          >
            <span>{link.icon}</span>
            <span>{link.label}</span>
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}