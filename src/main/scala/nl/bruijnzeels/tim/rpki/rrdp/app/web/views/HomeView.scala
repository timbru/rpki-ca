package nl.bruijnzeels.tim.rpki.rrdp.app.web.views

import scala.xml.Text
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.Main
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchor
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServer
import scala.xml.XML
import org.apache.commons.lang.StringEscapeUtils

class HomeView(ta: TrustAnchor, publicationServer: PublicationServer) extends View {

  def tab = Tabs.HomeTab
  def title = Text("RRDP Proof of concept server")
  def body = {
    <pre class="alert-message block-message alert monospace">{ ta.tal }</pre>
    <div class="alert-message block-message info">
      <div class="row">
        <div class="span12 center">Publication Server Details</div>
      </div>
      <div class="row">
        <div class="span6">Session Id</div>
        <div class="span6">{ publicationServer.sessionId } </div>
      </div>
      <div class="row">
        <div class="span6">Last serial</div>
        <div class="span6">{ publicationServer.serial } </div>
      </div>
      <div class="row">
        <div class="span6">Notification File</div>
        <div class="span6"><a href={PocDsl.RrdpNotifyUrl.toString}>{ PocDsl.RrdpNotifyUrl.toString }</a></div>
      </div>
    </div>

  }

}