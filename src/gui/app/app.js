import React, { Component } from 'react';
import ReactDOM from 'react-dom';
import { Router, Route, IndexRoute, hashHistory  } from 'react-router';
import Layout from './containers/Layout';
import Home from './containers/Home';
import Config from './containers/Config';

class Root extends Component {
  render() {
    return (
      <Router history={hashHistory}>
        <Route path="/" component={Layout}>
          <IndexRoute component={Home} />
          <Route path="config" component={Config} />
        </Route>
      </Router>
    );
  }
}

ReactDOM.render(<Root history={history} />, document.getElementById('root'));
