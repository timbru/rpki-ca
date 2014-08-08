package nl.bruijnzeels.tim.rpki.rrdp.app.web.controllers

import nl.bruijnzeels.tim.rpki.rrdp.app.web.views.HomeView

import org.scalatra.FlashMapSupport
import org.scalatra.ScalatraBase

trait ApplicationController extends ScalatraBase with FlashMapSupport {

  get("/") {
    new HomeView()
  }

}