package nl.bruijnzeels.tim.rpki.rrdp.app.web

import org.scalatra.ScalatraFilter
import scala.xml.Xhtml
import nl.bruijnzeels.tim.rpki.rrdp.app.web.views.View
import nl.bruijnzeels.tim.rpki.rrdp.app.web.views.Layouts
import nl.bruijnzeels.tim.rpki.rrdp.app.web.controllers.ApplicationController

abstract class WebFilter extends ScalatraFilter with ApplicationController {

  private def renderView: PartialFunction[Any, Any] = {
    case view: View =>
      contentType = "text/html"
      "<!DOCTYPE html>\n" + Xhtml.toXhtml(Layouts.standard(view))
  }

  override protected def renderPipeline = renderView orElse super.renderPipeline

}