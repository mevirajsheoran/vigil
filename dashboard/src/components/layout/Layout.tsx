import { Outlet } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";

/*
Layout is the "container" for all pages.

<Outlet /> is where React Router renders the current page component.
For example, if you're on /fingerprints, Outlet renders FingerprintsPage.

This way, every page gets the same sidebar and header without repeating code.
*/
export default function Layout() {
  return (
    <div className="flex min-h-screen bg-gray-950">
      <Sidebar />
      <div className="flex-1 flex flex-col">
        <Header />
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}