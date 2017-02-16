import React, { Component } from 'react';
import Radium, { Style }  from 'radium';
import {StyleRoot} from 'radium';

class Layout extends Component {
  constructor(props) {
    super(props);
    this.state = {};
  }
  getStyles() {
    const bgcolor = {
      default: "#202020"
    }
    return {
      landingFooter: {
        position: "absolute",
        bottom: "0",
        left: "0",
        right: "0",
        width: "100%"
      }
    };
  }

  render() {
    const styles = this.getStyles();
    return (
      <StyleRoot>
        <Style rules={{
          body: {
            backgroundColor: "#202020",
            color: "#717174",
            fontFamily: 'Helvetica Neue, Helvetica, Arial, sans-serif'
          }
        }} />
        <div>
          {this.props.children}
        </div>
      </StyleRoot>
    );
  }
}

export default Radium(Layout);
