import React, {Component} from 'react';
import './navigationBar.css';

class NavigationBar extends Component {
    render() {
        return (
            <div>
                <nav className="navbar navbar-expand-sm navbar-dark bg-custom">
                    <div className="container-fluid">
                        <button className="navbar-toggler" type="button" data-toggle="collapse" data-target="#nav-content" aria-controls="nav-content" aria-expanded="false" aria-label="Toggle navigation">
                            <span className="navbar-toggler-icon"></span>
                        </button>

                        <a className="navbar-brand" href="#">any Store</a>

                        <div className="collapse navbar-collapse" id="nav-content">
                            <ul className="navbar-nav mr-auto">
                                <li className="dropdown nav-link">
                                    <a href="#" className="dropbtn nav-item dropdown-toggle" data-toggle="dropdown">
                                        Dealer Management
                                        <b className="caret"></b>
                                    </a>
                                    <ul id="dealer-menu" className="dropdown-menu">
                                        <li><a href="#">Add Dealer Details</a></li>
                                        <li><a href="#">View Dealer Details</a></li>
                                    </ul>
                                </li>
                                <li className="nav-link">
                                    <a className="nav-item" href="#">Link 1</a>
                                </li>
                                <li className="nav-link">
                                    <a className="nav-item" href="#">Link 2</a>
                                </li>
                                <li className="nav-link">
                                    <a className="nav-item" href="#">Link 3</a>
                                </li>
                            </ul>
                            <form className="navbar-form form-inline my-2 my-lg-0">
                            <div className="form-group">
                                <input type="text" className="form-control mr-sm-2"  placeholder="Search"/>
                                <button className="btn btn-success my-2 my-sm-0">Search</button>
                            </div>
                        </form>
                        </div>
                    </div>
                </nav>
            </div>
        );
    }
}

export default NavigationBar;