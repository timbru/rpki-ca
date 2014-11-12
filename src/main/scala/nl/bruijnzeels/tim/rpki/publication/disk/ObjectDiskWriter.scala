package nl.bruijnzeels.tim.rpki.publication.disk

import nl.bruijnzeels.tim.rpki.ca.common.cqrs.AggregateRoot
import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventListener
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.publication.server.PublicationServerReceivedSnapshot
import java.net.URI
import java.io.File
import com.google.common.io.Files
import java.nio.file.Paths
import org.h2.store.fs.FileUtils
import org.h2.util.IOUtils
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventStore

/**
 * Writes/removes objects to/from disk so they can be exposed over rsync, or http for that matter.. 
 */
case class ObjectDiskWriter(baseUri: URI, baseDir: File) extends EventListener {
  
  override def handle(events: List[Event]) = {
    
    events.collect { case e: PublicationServerReceivedSnapshot => e }.lastOption match {
      case None => 
      case Some(snapshotReceived) => {
        val tmpDir = Files.createTempDir()
        
        snapshotReceived.snapshot.publishes.foreach { p =>
          getRelativeFilePath(p.uri) match { 
            case None => // 
            case Some(file) => {
              val fullFile = tmpDir.toPath().resolve(file.toPath()).toFile()
              Files.createParentDirs(fullFile)
              Files.write(p.repositoryObject.getEncoded, fullFile)
            }
          }
        }
        
        val oldDirTarget = Files.createTempDir()
        
        baseDir.renameTo(oldDirTarget)
        tmpDir.renameTo(baseDir)
        FileUtils.deleteRecursive(oldDirTarget.getAbsolutePath(), false)
      }
    }
  }
  
  def listen = EventStore.subscribe(this)
  
  def getRelativeFilePath(objectUri: URI): Option[File] = {
    val relativeUri = baseUri.relativize(objectUri)
    if (relativeUri.equals(objectUri)) {
      None
    } else {
      Some(new File(relativeUri.getPath))
    }
  }
}
