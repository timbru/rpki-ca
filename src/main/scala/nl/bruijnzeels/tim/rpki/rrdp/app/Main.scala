package nl.bruijnzeels.tim.rpki.rrdp.app

import java.util.EnumSet

import javax.servlet.DispatcherType

import nl.bruijnzeels.tim.rpki.rrdp.app.web.WebFilter

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

  val logger = Logger[this.type]

  startWebServer()

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
