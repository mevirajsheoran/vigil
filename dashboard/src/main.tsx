import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import App from "./App";
import "./index.css";

/*
QueryClient is the brain of React Query.

It manages:
- Cache: stores fetched data so we don't refetch on every render
- Background refetching: keeps data fresh automatically
- Error retries: retries failed requests up to 2 times

We create ONE QueryClient and pass it to QueryClientProvider.
Every hook (useOverview, useAttacks, etc.) reads from this
shared cache. If two components use useOverview() at the same
time, React Query only makes ONE network request, not two.
*/
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Retry failed requests 2 times before showing error
      retry: 2,
      // Data is considered "fresh" for 5 seconds
      // After that, React Query will refetch in the background
      staleTime: 5000,
    },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </React.StrictMode>
);