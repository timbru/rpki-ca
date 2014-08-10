package nl.bruijnzeels.tim.rpki.rrdp.app

import scala.language.postfixOps

import java.util.EnumSet

import javax.servlet.DispatcherType

import nl.bruijnzeels.tim.rpki.rrdp.app.web.WebFilter

import dsl.PocDsl.ChildId
import dsl.PocDsl.ChildResources
import dsl.PocDsl.ca
import dsl.PocDsl.create
import dsl.PocDsl.current
import dsl.PocDsl.ta
import grizzled.slf4j.Logger
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.DefaultServlet
import org.eclipse.jetty.servlet.FilterHolder
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder

object Main {

  def main(args: Array[String]): Unit = {
    System.setProperty("RRDP_SERVER_LOG_FILE", "log/server.log")
    new Main()
  }

}

class Main { main =>

  import Main._
  import dsl.PocDsl._

  val logger = Logger[this.type]

  setUpPublicationServer()
  setUpCas()
  publishCas()
  startWebServer()

  def setUpPublicationServer() = create publicationServer

  def setUpCas() = {
    create ta

    create ca ChildId
    ta addChild (current ca ChildId) withResources ChildResources
    ca withId ChildId addTa (current ta)
    ca withId ChildId update
  }

  def publishCas() = {
    ta publish

    ca withId ChildId publish
  }


  def startWebServer() = {
    val server = new Server(8080)
    val webFilter = new WebFilter {}

    val root = new ServletContextHandler(server, "/", ServletContextHandler.SESSIONS)
    root.setResourceBase(getClass.getResource("/public").toString)

    val defaultServletHolder = new ServletHolder(new DefaultServlet())
    defaultServletHolder.setName("default")
    defaultServletHolder.setInitParameter("dirAllowed", "false")
    root.addServlet(defaultServletHolder, "/*")

    root.addFilter(new FilterHolder(webFilter), "/*", EnumSet.allOf(classOf[DispatcherType]))

    sys.addShutdownHook({
      server.stop()
      logger.info("Terminating...")
    })
    server.start()
    logger.info("Welcome to the RPKI RRDP proof of concept server, now available on port 8080. Hit CTRL+C to terminate.")
  }

}