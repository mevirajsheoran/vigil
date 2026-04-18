import { BrowserRouter, Routes, Route } from "react-router-dom";
import Layout from "./components/layout/Layout";
import OverviewPage from "./pages/OverviewPage";
import LiveFeedPage from "./pages/LiveFeedPage";
import FingerprintsPage from "./pages/FingerprintsPage";
import FingerprintDetailPage from "./pages/FingerprintDetailPage";
import AttacksPage from "./pages/AttacksPage";
import AttackDetailPage from "./pages/AttackDetailPage";
import AnalyticsPage from "./pages/AnalyticsPage";

/*
App.tsx sets up client-side routing using React Router.

HOW REACT ROUTER WORKS:
- BrowserRouter: listens to the URL bar
- Routes: container for all route definitions
- Route: maps a URL path to a component

NESTED ROUTES:
The "/" route uses Layout as its component.
All child routes (fingerprints, attacks, etc.) render
inside Layout's <Outlet /> — so they all get the
sidebar and header automatically.

Example:
  URL: /attacks
  Renders: Layout → <Outlet/> → AttacksPage
  Result: Sidebar + Header + AttacksPage content
*/
export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          {/* index means this renders at exactly "/" */}
          <Route index element={<OverviewPage />} />
          <Route path="live" element={<LiveFeedPage />} />
          <Route
            path="fingerprints"
            element={<FingerprintsPage />}
          />
          <Route
            path="fingerprints/:id"
            element={<FingerprintDetailPage />}
          />
          <Route path="attacks" element={<AttacksPage />} />
          <Route
            path="attacks/:id"
            element={<AttackDetailPage />}
          />
          <Route
            path="analytics"
            element={<AnalyticsPage />}
          />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}