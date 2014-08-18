package nl.bruijnzeels.tim.rpki.rrdp.app.web.controllers

import nl.bruijnzeels.tim.rpki.rrdp.app.web.views.HomeView

import org.scalatra.FlashMapSupport
import org.scalatra.ScalatraBase
import nl.bruijnzeels.tim.rpki.rrdp.app.ApplicationOptions
import nl.bruijnzeels.tim.rpki.ca.certificateauthority.ta.TrustAnchorCommandDispatcher
import nl.bruijnzeels.tim.rpki.rrdp.app.dsl.PocDsl
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerCommandDispatcher
import nl.bruijnzeels.tim.rpki.publication.messages.ReferenceHash

trait ApplicationController extends ScalatraBase with FlashMapSupport {

  def currentTa = TrustAnchorCommandDispatcher.load(PocDsl.TrustAnchorId).get
  def currentPublicationServer = PublicationServerCommandDispatcher.load(PocDsl.PublicationServerId).get
  val rrdpFileStore = PocDsl.current.rrdpFileStore

  val TrustAnchorCertificatePath = "ta/ta.cer"
  val RrdpNotitifyPath = "notify/notify.xml"
  val RrdpFilesPath = "rrpd/"

  get("/") {
    new HomeView(currentTa, currentPublicationServer)
  }

  get("/ta/ta.cer") {

    contentType = "application/octet-stream"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    response.getOutputStream().write(currentTa.resourceClass.currentSigner.signingMaterial.currentCertificate.getEncoded())
  }

  get("/notify/notify.xml") {

    contentType = "application/xml"
    response.addHeader("Pragma", "public")
    response.addHeader("Cache-Control", "no-cache")

    response.getWriter().write(currentPublicationServer.notificationFile.toXml.toString)
  }

  get("/rrdp/:fileName") {

    val fileName = (params("fileName"))

    // Should end with .xml
    val hash = ReferenceHash(fileName.stripSuffix(".xml"))

    rrdpFileStore.retrieve(hash) match {
      case Some(bytes) => {
        contentType = "application/xml"
        response.addHeader("Pragma", "public")
        response.addHeader("Cache-Control", "no-cache")

        response.getWriter().write(new String(bytes, "UTF-8"))
      }
      case None => halt(404)
    }
  }
}

