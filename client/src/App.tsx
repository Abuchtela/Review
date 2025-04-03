import { Switch, Route } from "wouter";
import Home from "@/pages/Home";
import VulnerabilityView from "@/pages/VulnerabilityView";
import NotFound from "@/pages/not-found";

function App() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/vulnerability/:id" component={VulnerabilityView} />
      <Route component={NotFound} />
    </Switch>
  );
}

export default App;
