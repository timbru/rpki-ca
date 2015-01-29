package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventListener
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerUpdatedPublicationSet
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.StoredEvent

class PublicationServerUpdateListener(publicationServerId: UUID) extends EventListener {

  override def handle(events: List[StoredEvent]) = {
    val updates = events.map(_.event).collect { case e: SignerUpdatedPublicationSet => e }

    updates.foreach { update =>
      PublicationServerCommandDispatcher.load(publicationServerId) match {
        case None => // Log error?
        case Some(server) => PublicationServerCommandDispatcher.dispatch(
          PublicationServerPublish(server.versionedId, update.publishes ++ update.withdraws))
      }

    }

  }

}