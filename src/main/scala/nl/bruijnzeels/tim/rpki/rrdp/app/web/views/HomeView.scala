package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.Text
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.Main
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl

class HomeView extends View {

  def tab = Tabs.HomeTab
  def title = Text("RRDP Proof of concept server")
  def body = {
    <div class="alert-message block-message info" data-alert="alert">
      Trust Anchor Locator:
      <pre class="alert-message block-message info monospace">{ TrustAnchorCommandDispatcher.load(PocDsl.TrustAnchorId).get.tal }</pre>
    </div>
  }



}