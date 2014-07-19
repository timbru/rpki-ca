package nl.bruijnzeels.tim.rpki.ca.ta

case class TaCommandDispatcher() {

  def dispatch(command: TrustAnchorCommand) = {
    val existingTa = TrustAnchorStore.load(command.id)

    if (existingTa.isDefined && command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException("Can't create new TA with id " + command.id + ", TA with same id exists")
    }

    if (!existingTa.isDefined && !command.isInstanceOf[TrustAnchorCreate]) {
      throw new IllegalArgumentException("Can't find exisiting TA with id " + command.id + " for command")
    }

    val updatedTa = command match {
      case create: TrustAnchorCreate => TrustAnchorCreateCommandHandler.handle(create)
    }

    TrustAnchorStore.save(updatedTa)
  }
}

object TrustAnchorCreateCommandHandler {
  def handle(command: TrustAnchorCreate) = TrustAnchor.create(command.id, command.name, command.taCertificateUri, command.publicationUri, command.resources)
}


//
//trait TaCommandHandler[C <: TaCommand] {
//  def handle(command: C, ta: TrustAnchor): TrustAnchor
//}
//
//object TaPublishCommandHandler extends TaCommandHandler[TaPublish] {
//  override def handle(command: TaPublish, ta: TrustAnchor) = ta.publish()
//}
//
////object TaChildAddCommandHandler extends TaCommandHandler[TaChildAdd] {
////  override def handle(command: TaChildAdd, ta: TrustAnchor) = ta.addChild(command.childId)
////}
////
////object TaChildSetResourceEntitlementsCommandHandler extends TaCommandHandler[TaChildSetResourceEntitlements] {
////  override def handle(command: TaChildSetResourceEntitlements, ta: TrustAnchor) = ta.childSetResourceEntitlements(command.childId, command.entitlements)
////}
////
////object TaChildRequestResourceCertificateCommandHandler extends TaCommandHandler[TaChildRequestResourceCertificate] {
////  override def handle(command: TaChildRequestResourceCertificate, ta: TrustAnchor) = ta.childProcessResourceCertificateRequest(command.childId, command.request)
////}
//
