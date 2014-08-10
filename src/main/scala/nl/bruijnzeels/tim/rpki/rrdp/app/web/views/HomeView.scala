package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.Text
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.Main
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl

class HomeView extends View {

  def tab = Tabs.HomeTab
  def title = Text("RRDP Proof of concept server")
  def body = {
    <p>
      TAL:
      { TrustAnchorCommandDispatcher.load(PocDsl.TrustAnchorId).get.tal }
    </p>

  }

}