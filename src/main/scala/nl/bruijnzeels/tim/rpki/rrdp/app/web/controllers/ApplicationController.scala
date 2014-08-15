package nl.bruijnzeels.tim.rpki.rrdp.app.web.controllers

import nl.bruijnzeels.tim.rpki.rrdp.app.web.views.HomeView
import org.scalatra.FlashMapSupport
import org.scalatra.ScalatraBase
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCommandDispatcher

trait ApplicationController extends ScalatraBase with FlashMapSupport {

  import ApplicationOptions.rrdpBasePath

  def currentTa = TrustAnchorCommandDispatcher.load(PocDsl.TrustAnchorId).get
  def currentPublicationServer = PublicationServerCommandDispatcher.load(PocDsl.PublicationServerId).get

  def baseContext = "/" + rrdpBasePath

  get(baseContext) {
    new HomeView(currentTa, currentPublicationServer)
  }

  get(PocDsl.TrustAnchorCertUri.getPath()) {

    contentType = "application/octet-stream"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    response.getOutputStream().write(currentTa.resourceClass.currentSigner.signingMaterial.currentCertificate.getEncoded())
  }

  get(PocDsl.RrdpNotifyUrl.getPath()) {

    contentType = "application/xml"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    response.getWriter().write(currentPublicationServer.notificationFile.toXml.toString)
  }

}