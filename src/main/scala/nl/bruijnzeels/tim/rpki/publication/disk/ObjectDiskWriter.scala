/**
 * Copyright (c) 2014-2015 Tim Bruijnzeels
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
package nl.bruijnzeels.tim.rpki.publication.disk

import java.io.File
import java.net.URI

import com.google.common.io.Files
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.{EventListener, EventStore, StoredEvent}
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerReceivedSnapshot
import org.h2.store.fs.FileUtils

/**
 * Writes/removes objects to/from disk so they can be exposed over rsync, or http for that matter..
 */
case class ObjectDiskWriter(baseUri: URI, baseDir: File) extends EventListener {

  override def handle(events: List[StoredEvent]) = {

    events.map(_.event).collect { case e: PublicationServerReceivedSnapshot => e }.lastOption match {
      case None =>
      case Some(snapshotReceived) => {

        val newDir = baseDir.toPath().resolve("new/").toFile()

        snapshotReceived.snapshot.publishes.foreach { p =>
          getRelativeFilePath(p.uri) match {
            case None => //
            case Some(file) => {
              val fullFile = newDir.toPath().resolve(file.toPath()).toFile()
              Files.createParentDirs(fullFile)
              Files.write(p.repositoryObject.getEncoded, fullFile)
            }
          }
        }

        val currentDir = baseDir.toPath().resolve("current/").toFile()

        val oldDir = baseDir.toPath().resolve("old/").toFile()

        if (currentDir.exists()) { Files.move(currentDir, oldDir) }

        Files.move(newDir, currentDir)

        if (oldDir.exists()) { FileUtils.deleteRecursive(oldDir.getAbsolutePath(), false) }
      }
    }
  }

  def listen() = EventStore.subscribe(this)

  def getRelativeFilePath(objectUri: URI): Option[File] = {
    val relativeUri = baseUri.relativize(objectUri)
    if (relativeUri.equals(objectUri)) {
      None
    } else {
      Some(new File(relativeUri.getPath))
    }
  }
}
