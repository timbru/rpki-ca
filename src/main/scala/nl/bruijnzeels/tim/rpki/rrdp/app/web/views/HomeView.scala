package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.Text

class HomeView extends View {

  def tab = Tabs.HomeTab
  def title = Text("RRDP Proof of concept server")
  def body = <p>Welcome to the RRDP proof of concept server</p>

}