package nl.bruijnzeels.tim.rpki.publication.server

import java.util.UUID
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.EventListener
import nl.bruijnzeels.tim.rpki.ca.common.cqrs.Event
import nl.bruijnzeels.tim.rpki.ca.rc.signer.SignerUpdatedPublicationSet

class PublicationServerUpdateListener(publicationServerId: UUID) extends EventListener {

  override def handle(events: List[Event]) = {
    val updates = events.collect { case e: SignerUpdatedPublicationSet => e }

    updates.foreach { update =>
      PublicationServerCommandDispatcher.dispatch(
        PublicationServerPublish(publicationServerId, update.publishes ++ update.withdraws))
    }

  }

}