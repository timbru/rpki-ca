package nl.bruijnzeels.tim.rpki.rrdp.app

import scala.language.postfixOps

import java.util.EnumSet

import javax.servlet.DispatcherType

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import nl.bruijnzeels.tim.rpki.rrdp.app.web.WebFilter

import ApplicationOptions.rrdpPort
import dsl.PocDsl.ChildId
import dsl.PocDsl.ChildResources
import dsl.PocDsl.certificateAuthority
import dsl.PocDsl.create
import dsl.PocDsl.current
import dsl.PocDsl.publicationServer
import dsl.PocDsl.trustAnchor
import grizzled.slf4j.Logger
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.DefaultServlet
import org.eclipse.jetty.servlet.FilterHolder
import org.eclipse.jetty.servlet.ServletContextHandler
import org.eclipse.jetty.servlet.ServletHolder

object Main {

  def main(args: Array[String]): Unit = {
    new Main()
  }

}

class Main { main =>

  import Main._

  import dsl.PocDsl._
  import ApplicationOptions._

  import scala.concurrent.duration._
  import actorSystem.dispatcher

  implicit val actorSystem = akka.actor.ActorSystem()

  val logger = Logger[this.type]

  EventStore.clear // EventStore is not thread safe, and it's keeping stuff in memory, so need to clear this when running this multiple times in the same JVM (like from an IDE..)

  setUpPublicationServer()
  setUpCas()
  actorSystem.scheduler.schedule(initialDelay = 0.seconds, interval = 10.seconds) { publishCas() }
  startWebServer()

  def setUpPublicationServer() = {
    logger.info("Setting up publication server")
    create publicationServer()
    publicationServer listen
  }

  def setUpCas() = {
    logger.info("Setting up TA and CA")
    create trustAnchor ()
    create certificateAuthority ChildId
    trustAnchor addChild (current certificateAuthority ChildId) withResources ChildResources
    certificateAuthority withId ChildId addTa (current trustAnchor)
    certificateAuthority withId ChildId update
  }

  def publishCas() = {
    logger.info("Publishing TA and CA")
    trustAnchor publish ()
    certificateAuthority withId ChildId publish
  }

  def startWebServer() = {
    val server = new Server(rrdpPort)
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
    logger.info(s"Welcome to the RPKI RRDP proof of concept server, now available on port ${rrdpPort}. Hit CTRL+C to terminate.")
  }

}