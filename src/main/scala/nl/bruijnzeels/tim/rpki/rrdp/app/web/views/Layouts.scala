package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.NodeSeq
import org.joda.time.DateTime

object Layouts {

  def none(view: View): NodeSeq = {
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
      </head>
      <body>{ view.body }</body>
    </html>
  }

  def standard(view: View): NodeSeq = {
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <title>RRDP - { view.title }</title>
        <link rel="stylesheet" href="/stylesheets/bootstrap/1.3.0/bootstrap.css"/>
        <link rel="stylesheet" href="/stylesheets/application.css"/>
        <script src="/javascript/datatables/1.8.2/jquery.js"/>
        <script src="/javascript/datatables/1.8.2/jquery.dataTables.min.js"/>
        <script src="/javascript/bootstrap/1.3.0/bootstrap-alerts.js"/>
        <script src="/javascript/bootstrap/1.3.0/bootstrap-twipsy.js"/>
        <script src="/javascript/bootstrap/1.3.0/bootstrap-popover.js"/>
        <script src="/javascript/bootstrap/1.4.0/bootstrap-dropdown.js"/>
      </head>
      <body>
        <div class="topbar">
          <div class="fill">
            <div class="container">
              <a class="brand" href="/">RPKI RRDP</a>
              <ul class="nav">
                {
                  for (tab <- Tabs.visibleTabs) yield {
                    <li class={ if (tab == view.tab) "active" else "" }><a href={ tab.url }>{ tab.text }</a></li>
                  }
                }
              </ul>
            </div>
          </div>
        </div>
        <div class="container">
          <div class="page-header">
            <h1>{ view.title }</h1>
          </div>
          { view.body }
          <footer>
            <div class="copyright">
              <img src="/images/ncc-logo.png" align="middle"/>
              &nbsp;
              Copyright &copy; 2014 the Réseaux IP Européens Network Coordination Centre RIPE NCC. All rights restricted. Version 0.1
            </div>
          </footer>
        </div>
      </body>
    </html>
  }

}