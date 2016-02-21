/**
 * Copyright (c) 2014-2016 Tim Bruijnzeels
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of this software, nor the names of its contributors, nor
 *     the names of the contributors' employers may be used to endorse or promote
 *     products derived from this software without specific prior written
 *     permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package nl.bruijnzeels.tim.rpki.app.main

import java.util.EnumSet
import javax.servlet.DispatcherType

import grizzled.slf4j.Logger
import nl.bruijnzeels.tim.rpki.app.web.WebFilter
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.servlet.{DefaultServlet, FilterHolder, ServletContextHandler, ServletHolder}

import scala.language.postfixOps

object Main {

  def main(args: Array[String]): Unit = {
    new Main()
  }

}

class Main { main =>

  import ApplicationOptions._
  import Dsl._
  import actorSystem.dispatcher

  import scala.concurrent.duration._

  implicit val actorSystem = akka.actor.ActorSystem()

  val logger = Logger[this.type]

  EventStore.clear // EventStore is not thread safe, and it's keeping stuff in memory, so need to clear this when running this multiple times in the same JVM (like from an IDE..)

  setUpPublicationServer()
  setUpCas()
  actorSystem.scheduler.schedule(initialDelay = 0.seconds, interval = 10.minutes) { publishCas() }
  startWebServer()

  def setUpPublicationServer() = {
    logger.info("Setting up publication server")
    create publicationServer()
    publicationServer listen()
    diskWriter listen()
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

    val root = new ServletContextHandler(server, "/rpki-ca", ServletContextHandler.SESSIONS)
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